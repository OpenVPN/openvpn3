#ifndef OPENVPN_TRANSPORT_UDPLINK_H
#define OPENVPN_TRANSPORT_UDPLINK_H

#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/sessionstats.hpp>

#if defined(OPENVPN_DEBUG_UDPLINK) && OPENVPN_DEBUG_UDPLINK >= 1
#define OPENVPN_LOG_UDPLINK_ERROR(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_UDPLINK_ERROR(x)
#endif

#if defined(OPENVPN_DEBUG_UDPLINK) && OPENVPN_DEBUG_UDPLINK >= 3
#define OPENVPN_LOG_UDPLINK_VERBOSE(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_UDPLINK_VERBOSE(x)
#endif

namespace openvpn {
  namespace UDPTransport {

    typedef boost::asio::ip::udp::endpoint Endpoint;

    struct PacketFrom
    {
      typedef ScopedPtr<PacketFrom> SPtr;
      BufferAllocated buf;
      Endpoint sender_endpoint;
    };

    template <typename ReadHandler>
    class Link : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<Link> Ptr;

      Link(ReadHandler read_handler_arg,
	   boost::asio::ip::udp::socket& socket_arg,
	   const Frame::Ptr& frame_arg,
	   const SessionStats::Ptr& stats_arg)
	: socket(socket_arg),
	  halt(false),
	  read_handler(read_handler_arg),
	  frame(frame_arg),
	  frame_context((*frame_arg)[Frame::READ_LINK_UDP]),
	  stats(stats_arg)
      {
      }

      bool send(const Buffer& buf, Endpoint* endpoint)
      {
	if (!halt)
	  {
	    try {
	      const size_t wrote = endpoint
		? socket.send_to(buf.const_buffers_1(), *endpoint)
		: socket.send(buf.const_buffers_1());
	      stats->inc_stat(SessionStats::BYTES_OUT, wrote);
	      if (wrote == buf.size())
		return true;
	      else
		{
		  OPENVPN_LOG_UDPLINK_ERROR("UDP partial send error");
		  stats->error(Error::NETWORK_ERROR);
		  return false;
		}
	    }
	    catch (boost::system::system_error& e)
	      {
		OPENVPN_LOG_UDPLINK_ERROR("UDP send error: " << e.what());
		stats->error(Error::NETWORK_ERROR);
		return false;
	      }
	  }
	else
	  return false;
      }

      void start(const int n_parallel)
      {
	if (!halt)
	  {
	    for (int i = 0; i < n_parallel; i++)
	      queue_read(NULL);
	  }
      }

      void stop() {
	halt = true;
      }

      ~Link() { stop(); }

    private:
      void queue_read(PacketFrom *udpfrom)
      {
	OPENVPN_LOG_UDPLINK_VERBOSE("UDPLink::queue_read");
	if (!udpfrom)
	  udpfrom = new PacketFrom();
	frame_context.prepare(udpfrom->buf);
	socket.async_receive_from(frame_context.mutable_buffers_1(udpfrom->buf),
				  udpfrom->sender_endpoint,
				  asio_dispatch_read(&Link::handle_read, this, udpfrom));
      }

      void handle_read(PacketFrom *udpfrom, const boost::system::error_code& error, const size_t bytes_recvd)
      {
	OPENVPN_LOG_UDPLINK_VERBOSE("UDPLink::handle_read: " << error.message());
	PacketFrom::SPtr pfp(udpfrom);
	if (!halt)
	  {
	    if (bytes_recvd)
	      {
		if (!error)
		  {
		    OPENVPN_LOG_UDPLINK_VERBOSE("UDP from " << pfp->sender_endpoint);
		    pfp->buf.set_size(bytes_recvd);
		    stats->inc_stat(SessionStats::BYTES_IN, bytes_recvd);
		    read_handler->udp_read_handler(pfp);
		  }
		else
		  {
		    OPENVPN_LOG_UDPLINK_ERROR("UDP recv error: " << error.message());
		    stats->error(Error::NETWORK_ERROR);
		  }
	      }
	    queue_read(pfp.release()); // reuse PacketFrom object if still available
	  }
      }

      boost::asio::ip::udp::socket& socket;
      bool halt;
      ReadHandler read_handler;
      Frame::Ptr frame;
      const Frame::Context& frame_context;
      SessionStats::Ptr stats;
    };
  }
} // namespace openvpn

#endif
