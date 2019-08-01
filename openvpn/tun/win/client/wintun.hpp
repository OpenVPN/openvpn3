#pragma once

#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/persist/tunpersist.hpp>
#include <openvpn/tun/win/client/setupbase.hpp>
#include <openvpn/tun/win/client/clientconfig.hpp>
#include <openvpn/win/modname.hpp>

#define TUN_IOCTL_REGISTER_RINGS CTL_CODE(51820U, 0x970U, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define TUN_IOCTL_FORCE_CLOSE_HANDLES CTL_CODE(51820U, 0x971U, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA)

#define WINTUN_RING_CAPACITY 0x800000
#define WINTUN_RING_TRAILING_BYTES 0x10000
#define WINTUN_RING_FRAMING_SIZE 12
#define WINTUN_MAX_PACKET_SIZE 0xffff
#define WINTUN_PACKET_ALIGN 4

namespace openvpn {
  namespace TunWin {

    class WintunClient : public TunClient
    {
      typedef RCPtr<WintunClient> Ptr;

    public:
      WintunClient(openvpn_io::io_context& io_context_arg,
		   ClientConfig* config_arg,
		   TunClientParent& parent_arg)
	: io_context(io_context_arg),
	  config(config_arg),
	  parent(parent_arg),
	  state(new TunProp::State()),
	  ring_send_tail_moved_event(io_context_arg),
	  frame(config_arg->frame)
      {

      }

      // Inherited via TunClient
      void tun_start(const OptionList& opt, TransportClient& transcli, CryptoDCSettings&) override
      {
	halt = false;

	try {
	  const IP::Addr server_addr = transcli.server_endpoint_addr();

	  // notify parent
	  parent.tun_pre_tun_config();

	  // parse pushed options
	  TunBuilderCapture::Ptr po(new TunBuilderCapture());
	  TunProp::configure_builder(po.get(),
				     state.get(),
				     config->stats.get(),
				     server_addr,
				     config->tun_prop,
				     opt,
				     nullptr,
				     false);
	  OPENVPN_LOG("CAPTURED OPTIONS:" << std::endl << po->to_string());

	  // create new tun setup object
	  tun_setup = config->new_setup_obj(io_context);

	  // open/config TAP
	  {
	    std::ostringstream os;
	    auto os_print = Cleanup([&os]() { OPENVPN_LOG_STRING(os.str()); });
	    driver_handle = tun_setup->establish(*po, Win::module_name(), config->stop, os);
	  }

	  // assert ownership over TAP device handle
	  tun_setup->confirm();

	  register_rings();



	  openvpn_io::post([self=Ptr(this)](){
	    self->read();
	  });

	  parent.tun_connected(); // signal that we are connected
	}
	catch (const std::exception& e)
	  {
	    stop();
	    Error::Type err = Error::TUN_SETUP_FAILED;
	    const ExceptionCode* ec = dynamic_cast<const ExceptionCode*>(&e);
	    if (ec && ec->code_defined())
	      err = ec->code();
	    parent.tun_error(err, e.what());
	  }
      }

      void stop() override
      {
	if (!halt)
	  {
	    halt = true;
	    unregister_rings();

	    std::ostringstream os;
	    auto os_print = Cleanup([&os]() { OPENVPN_LOG_STRING(os.str()); });
	    tun_setup->destroy(os);
	  }
      }

      void set_disconnect() override
      {

      }

      bool tun_send(BufferAllocated& buf) override
      {
	ULONG head = rings.receive.ring->head;
	if (head > WINTUN_RING_CAPACITY)
	  {
	    if (head == 0xFFFFFFFF)
	      parent.tun_error(Error::TUN_WRITE_ERROR, "invalid ring head/tail or bogus packet received");
	    return false;
	  }

	ULONG tail = rings.receive.ring->tail;
	if (tail >= WINTUN_RING_CAPACITY)
	  return false;

	ULONG aligned_packet_size = packet_align(sizeof(TUN_PACKET_HEADER) + buf.size());
	ULONG buf_space = wrap(head - tail - WINTUN_PACKET_ALIGN);
	if (aligned_packet_size > buf_space)
	  {
	    OPENVPN_LOG("ring is full");
	    return false;
	  }

	// copy packet size and data into ring
	TUN_PACKET* packet = (TUN_PACKET*)& rings.receive.ring->data[tail];
	packet->size = buf.size();
	std::memcpy(packet->data, buf.data(), buf.size());

	// move ring tail
	tail = wrap(tail + aligned_packet_size);
	rings.receive.ring->tail = tail;
	if (rings.receive.ring->alertable != 0)
	  SetEvent(rings.receive.tail_moved);

	return true;
      }

      std::string tun_name() const override
      {
	return "wintun";
      }

      std::string vpn_ip4() const override
      {
	if (state->vpn_ip4_addr.specified())
	  return state->vpn_ip4_addr.to_string();
	else
	  return "";
      }

      std::string vpn_ip6() const override
      {
	if (state->vpn_ip6_addr.specified())
	  return state->vpn_ip6_addr.to_string();
	else
	  return "";
      }

      std::string vpn_gw4() const override
      {
	if (state->vpn_ip4_gw.specified())
	  return state->vpn_ip4_gw.to_string();
	else
	  return "";
      }

      std::string vpn_gw6() const override
      {
	if (state->vpn_ip6_gw.specified())
	  return state->vpn_ip6_gw.to_string();
	else
	  return "";
      }

    private:
      void read()
      {
	if (halt)
	  return;

	ULONG head = rings.send.ring->head;
	if (head >= WINTUN_RING_CAPACITY)
	  {
	    parent.tun_error(Error::TUN_ERROR, "ring head exceeds ring capacity");
	    return;
	  }

	ULONG tail = rings.send.ring->tail;
	if (tail >= WINTUN_RING_CAPACITY)
	  {
	    parent.tun_error(Error::TUN_ERROR, "ring tail exceeds ring capacity");
	    return;
	  }

	// tail has moved?
	if (head == tail)
	  {
	    ring_send_tail_moved_event.async_wait([self=Ptr(this)](const openvpn_io::error_code& error) {
	      if (!error)
		self->read();
	      else
		{
		  if (!self->halt)
		    self->parent.tun_error(Error::TUN_ERROR, "error waiting on ring send tail moved");
		}
	    });
	    return;
	  }

	// read buffer content
	ULONG content_len = wrap(tail - head);
	if (content_len < sizeof(TUN_PACKET_HEADER))
	  {
	    parent.tun_error(Error::TUN_ERROR, "incomplete packet header in send ring");
	    return;
	  }

	TUN_PACKET* packet = (TUN_PACKET*)& rings.send.ring->data[head];
	if (packet->size > WINTUN_MAX_PACKET_SIZE)
	  {
	    parent.tun_error(Error::TUN_ERROR, "packet too big in send ring");
	    return;
	  }

	ULONG aligned_packet_size = packet_align(sizeof(TUN_PACKET_HEADER) + packet->size);
	if (aligned_packet_size > content_len)
	  {
	    parent.tun_error(Error::TUN_ERROR, "incomplete packet in send ring");
	    return;
	  }

	frame->prepare(Frame::READ_TUN, buf);

	buf.write(packet->data, packet->size);

	head = wrap(head + aligned_packet_size);
	rings.send.ring->head = head;

	parent.tun_recv(buf);

	if (!halt)
	  {
	    openvpn_io::post(io_context, [self=Ptr(this)]() {
	      self->read();
	    });
	  }
      }

      void register_rings()
      {
	ZeroMemory(&rings, sizeof(rings));

	rings.receive.ring = new TUN_RING();
	ZeroMemory(rings.receive.ring, sizeof(rings.receive.ring));
	rings.receive.tail_moved = CreateEvent(NULL, FALSE, FALSE, NULL);
	rings.receive.ring_size = sizeof(rings.receive.ring->data);

	rings.send.ring = new TUN_RING();
	ZeroMemory(rings.send.ring, sizeof(rings.send.ring));
	rings.send.tail_moved = CreateEvent(NULL, FALSE, FALSE, NULL);
	rings.send.ring_size = sizeof(rings.send.ring->data);

	ring_send_tail_moved_event.assign(rings.send.tail_moved);

	{
	  Win::Impersonate imp(true);

	  if (!DeviceIoControl(driver_handle, TUN_IOCTL_REGISTER_RINGS, &rings, sizeof(rings), NULL, NULL, NULL, NULL))
	    {
	      const Win::LastError err;
	      throw ErrorCode(Error::TUN_REGISTER_RINGS_ERROR, true, "Error registering ring buffers: " + err.message());
	    }
	}
      }

      void unregister_rings()
      {
	// delete ring buffers
	delete rings.send.ring;
	rings.send.ring = nullptr;

	delete rings.receive.ring;
	rings.receive.ring = nullptr;

	// close event handles
	CloseHandle(rings.receive.tail_moved);

	CloseHandle(driver_handle);
      }

      struct TUN_RING {
	volatile ULONG head;
	volatile ULONG tail;
	volatile LONG alertable;
	UCHAR data[WINTUN_RING_CAPACITY + WINTUN_RING_TRAILING_BYTES + WINTUN_RING_FRAMING_SIZE];
      };

      struct TUN_REGISTER_RINGS
      {
	struct
	{
	  ULONG ring_size;
	  TUN_RING* ring;
	  HANDLE tail_moved;
	} send, receive;
      };

      struct TUN_PACKET_HEADER
      {
	uint32_t size;
      };

      struct TUN_PACKET
      {
	uint32_t size;
	UCHAR data[WINTUN_MAX_PACKET_SIZE];
      };


      ULONG packet_align(ULONG size)
      {
	return (size + (WINTUN_PACKET_ALIGN - 1)) & ~(WINTUN_PACKET_ALIGN - 1);
      }

      ULONG wrap(ULONG value)
      {
	return value & (WINTUN_RING_CAPACITY - 1);
      }

      openvpn_io::io_context& io_context;
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunProp::State::Ptr state;
      TunWin::SetupBase::Ptr tun_setup;

      TUN_REGISTER_RINGS rings = {};

      BufferAllocated buf;

      Frame::Ptr frame;

      bool halt;

      HANDLE driver_handle = NULL;

      openvpn_io::windows::object_handle ring_send_tail_moved_event;
    };
  }
}
