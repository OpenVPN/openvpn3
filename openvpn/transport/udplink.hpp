#ifndef OPENVPN_TRANSPORT_UDPLINK_H
#define OPENVPN_TRANSPORT_UDPLINK_H

#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/dispatch.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/log.hpp>
#include <openvpn/log/protostats.hpp>

#ifdef OPENVPN_DEBUG_UDPLINK
#define OPENVPN_LOG_UDPLINK(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_UDPLINK(x)
#endif

namespace openvpn {

  template <typename ReadHandler>
  class UDPLinkTemplate : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<UDPLinkTemplate> Ptr;

    enum BindType {
      LOCAL_BIND,       // (server) bind locally
      REMOTE_CONNECT,   // (client) don't bind locally, connect to explicit remote endpoint
    };

    typedef boost::asio::ip::udp::endpoint Endpoint;

    struct PacketFrom
    {
      typedef ScopedPtr<PacketFrom> SPtr;
      BufferAllocated buf;
      Endpoint sender_endpoint;
    };

    UDPLinkTemplate(boost::asio::io_service& io_service,
		    ReadHandler read_handler,
		    const Frame::Ptr& frame,
		    const ProtoStats::Ptr& stats,
		    BindType bt,
		    const Endpoint& endpoint,
		    const bool reuse_addr=false)
      : socket_(io_service),
	read_handler_(read_handler),
	frame_(frame),
	stats_(stats)
    {
      if (bt == LOCAL_BIND)
	{
	  socket_.open(endpoint.protocol());
	  if (reuse_addr)
	    socket_.set_option(boost::asio::ip::udp::socket::reuse_address(true));
	  socket_.bind(endpoint);
	}
      else if (bt == REMOTE_CONNECT)
	{
	  socket_.open(endpoint.protocol());
	  socket_.connect(endpoint);
	}
    }

    bool send(const Buffer& buf, Endpoint* endpoint)
    {
      try {
	const size_t wrote = endpoint
	  ? socket_.send_to(buf.const_buffers_1(), *endpoint)
	  : socket_.send(buf.const_buffers_1());
	stats_->inc_stat(ProtoStats::BYTES_OUT, wrote);
	if (wrote == buf.size())
	  return true;
	else
	  {
	    OPENVPN_LOG_UDPLINK("UDP partial send error");
	    stats_->error(ProtoStats::NETWORK_ERROR);
	    return false;
	  }
      }
      catch (boost::system::system_error& e)
	{
	  OPENVPN_LOG_UDPLINK("UDP send error: " << e.what());
	  stats_->error(ProtoStats::NETWORK_ERROR);
	  return false;
	}
    }

    void start(const int n_parallel)
    {
      for (int i = 0; i < n_parallel; i++)
	queue_read(NULL);
    }

    void stop() {
      halt_ = true;
      socket_.close();
    }

  private:
    void queue_read(PacketFrom *udpfrom)
    {
      //OPENVPN_LOG_UDPLINK("UDPLink::queue_read");
      if (!udpfrom)
	udpfrom = new PacketFrom();
      frame_->prepare(Frame::READ_LINK_UDP, udpfrom->buf);

      socket_.async_receive_from(udpfrom->buf.mutable_buffers_1(),
				 udpfrom->sender_endpoint,
				 asio_dispatch_read(&UDPLinkTemplate::handle_read, this, udpfrom)); // consider: this->shared_from_this()
    }

    void handle_read(PacketFrom *udpfrom, const boost::system::error_code& error, const size_t bytes_recvd)
    {
      //OPENVPN_LOG_UDPLINK("UDPLink::handle_read: " << error.message());
      typename PacketFrom::SPtr pfp(udpfrom);
      if (!halt_)
	{
	  if (!error)
	    {
	      pfp->buf.set_size(bytes_recvd);
	      stats_->inc_stat(ProtoStats::BYTES_IN, bytes_recvd);
	      read_handler_->udp_read_handler(pfp);
	    }
	  else
	    {
	      OPENVPN_LOG_UDPLINK("UDP Read Error: " << error);
	      stats_->error(ProtoStats::NETWORK_ERROR);
	    }
	  queue_read(pfp.release()); // reuse PacketFrom object if still available
	}
    }

    boost::asio::ip::udp::socket socket_;
    bool halt_;
    ReadHandler read_handler_;
    const Frame::Ptr frame_;
    ProtoStats::Ptr stats_;
  };
} // namespace openvpn

#endif
