#ifndef OPENVPN_LINK_UDPLINK_H
#define OPENVPN_LINK_UDPLINK_H

#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/weak_ptr.hpp>
#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/log.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/iostats.hpp>
#include <openvpn/common/dispatch.hpp>

namespace openvpn {

  struct UDPPacketFrom
  {
    typedef boost::asio::ip::udp::endpoint Endpoint;
    explicit UDPPacketFrom(size_t capacity) : buf(capacity) {}
    BufferAllocated buf;
    Endpoint sender_endpoint;
  };

  template <typename ReadHandler>
  class UDPLink
    : public boost::enable_shared_from_this< UDPLink<ReadHandler> >,
      private boost::noncopyable
  {
  public:
    enum bind_type {
      local_bind,       // (server) bind locally
      remote_connect,   // (client) don't bind locally, connect to explicit remote endpoint
    };

    typedef UDPPacketFrom::Endpoint Endpoint;
    typedef IOStats::Stats Stats;

    UDPLink(boost::asio::io_service& io_service,
	    ReadHandler read_handler,
	    bind_type bt,
	    const boost::asio::ip::address& address,
	    int port,
	    const bool reuse_addr=false,
	    const size_t buf_size=1500)
      : socket_(io_service),
	buf_size_(buf_size),
	read_handler_(read_handler)
    {
      if (bt == local_bind)
	{
	  Endpoint local_endpoint(address, port);
	  socket_.open(local_endpoint.protocol());
	  if (reuse_addr)
	    socket_.set_option(boost::asio::ip::udp::socket::reuse_address(true));
	  socket_.bind(local_endpoint);
	}
      else if (bt == remote_connect)
	{
	  Endpoint remote_endpoint(address, port);
	  socket_.open(remote_endpoint.protocol());
	  socket_.connect(remote_endpoint);
	}
    }

    void send(Buffer* buf, Endpoint* endpoint)
    {
      try {
	const size_t wrote = endpoint
	  ? socket_.send_to(buf->const_buffers_1(), *endpoint)
	  : socket_.send(buf->const_buffers_1());
	stats_.add_write_bytes(wrote);
	if (wrote != buf->size())
	  OPENVPN_LOG("UDP partial send error");
      }
      catch (boost::system::system_error& e)
	{
	  OPENVPN_LOG("UDP send error: " << e.what());
	}
    }

    Stats stats() { return stats_.get(); }
    void log() { stats_.log("UDP"); }

    void start(const int n_parallel)
    {
      for (int i = 0; i < n_parallel; i++)
	queue_read(NULL);
    }

    void stop() {
      halt_ = true;
      socket_.close();
    }

    virtual ~UDPLink() {
    }

  private:
    void queue_read(UDPPacketFrom *udpfrom)
    {
      //OPENVPN_LOG("UDPLink::queue_read"); // fixme
      if (!udpfrom)
	udpfrom = new UDPPacketFrom(buf_size_);

      socket_.async_receive_from(udpfrom->buf.mutable_buffers_1(),
				 udpfrom->sender_endpoint,
				 asio_dispatch_read(&UDPLink::handle_read, this, udpfrom)); // consider: this->shared_from_this()
    }

    void handle_read(UDPPacketFrom *udpfrom, const boost::system::error_code& error, const size_t bytes_recvd)
    {
      //OPENVPN_LOG("UDPLink::handle_read: " << error.message()); // fixme
      ScopedPtr<UDPPacketFrom> suf(udpfrom);
      if (!halt_)
	{
	  if (!error)
	    {
	      suf->buf.set_size(bytes_recvd);
	      stats_.add_read_bytes(bytes_recvd);
	      try
		{
		  read_handler_(suf);
		}
	      catch (boost::bad_weak_ptr &e)
		{
		  // read handler has gone out of scope, don't requeue
		  return;
		}
	    }
	  else
	    OPENVPN_LOG("UDP Read Error: " << error);
	  queue_read(suf.release()); // reuse UDPPacketFrom object if still available
	}
    }

    boost::asio::ip::udp::socket socket_;
    bool halt_;
    const size_t buf_size_;
    ReadHandler read_handler_;
    IOStats stats_;
  };
} // namespace openvpn

#endif
