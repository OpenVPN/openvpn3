#ifndef OPENVPN_TRANSPORT_TCPLINK_H
#define OPENVPN_TRANSPORT_TCPLINK_H

#include <deque>

#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/log.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/transport/pktstream.hpp>

#if defined(OPENVPN_DEBUG_TCPLINK) && OPENVPN_DEBUG_TCPLINK >= 1
#define OPENVPN_LOG_TCPLINK_ERROR(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_TCPLINK_ERROR(x)
#endif

#if defined(OPENVPN_DEBUG_TCPLINK) && OPENVPN_DEBUG_TCPLINK >= 3
#define OPENVPN_LOG_TCPLINK_VERBOSE(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_TCPLINK_VERBOSE(x)
#endif

namespace openvpn {
  namespace TCPTransport {

    typedef boost::asio::ip::tcp::endpoint Endpoint;

    struct PacketFrom
    {
      typedef ScopedPtr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    template <typename ReadHandler>
    class Link : public RC<thread_unsafe_refcount>
    {
      typedef std::deque<BufferPtr> Queue;

    public:
      typedef boost::intrusive_ptr<Link> Ptr;

      Link(ReadHandler read_handler_arg,
	   boost::asio::ip::tcp::socket& socket_arg,
	   const size_t send_queue_max_size_arg,
	   const size_t free_list_max_size_arg,
	   const Frame::Ptr& frame_arg,
	   const SessionStats::Ptr& stats_arg)
	: socket(socket_arg),
	  halt(false),
	  read_handler(read_handler_arg),
	  frame(frame_arg),
	  frame_context((*frame_arg)[Frame::READ_LINK_TCP]),
	  stats(stats_arg),
	  send_queue_max_size(send_queue_max_size_arg),
	  free_list_max_size(free_list_max_size_arg)
      {
      }

      bool send(BufferAllocated& b)
      {
	if (!halt && b.size() <= 0xFFFF)
	  {
	    if (queue.size() < send_queue_max_size)
	      {
		BufferPtr buf;
		if (!free_list.empty())
		  {
		    buf = free_list.front();
		    free_list.pop_front();
		  }
		else
		  buf.reset(new BufferAllocated());
		buf->swap(b);
		PacketStream::prepend_size(*buf);
		queue.push_back(buf);
		if (queue.size() == 1) // send operation not currently active?
		  queue_send();
		return true;
	      }
	    else
	      {
		stats->error(Error::TCP_OVERFLOW);
		read_handler->tcp_error_handler("TCP_OVERFLOW");
		stop();
	      }
	  }
	return false;
      }

      void start()
      {
	queue_recv(NULL);
      }

      void stop()
      {
	halt = true;
      }

      ~Link() { stop(); }

    private:
      void queue_send()
      {
	BufferAllocated& buf = *queue.front();
	socket.async_send(buf.const_buffers_1(),
			  asio_dispatch_write(&Link::handle_send, this));
      }

      void handle_send(const boost::system::error_code& error, const size_t bytes_sent)
      {
	if (!halt)
	  {
	    if (!error)
	      {
		OPENVPN_LOG_TCPLINK_VERBOSE("TCP send size=" << bytes_sent);
		stats->inc_stat(SessionStats::BYTES_OUT, bytes_sent);

		BufferPtr buf = queue.front();
		if (bytes_sent == buf->size())
		  {
		    queue.pop_front();
		    if (free_list.size() < free_list_max_size)
		      {
			buf->reset_content();
			free_list.push_back(buf); // recycle the buffer for later use
		      }
		  }
		else if (bytes_sent < buf->size())
		  buf->advance(bytes_sent);
		else
		  {
		    stats->error(Error::TCP_OVERFLOW);
		    read_handler->tcp_error_handler("TCP_INTERNAL_ERROR"); // error sent more bytes than we asked for
		    stop();
		    return;
		  }
	      }
	    else
	      {
		OPENVPN_LOG_TCPLINK_ERROR("TCP send error: " << error.message());
		stats->error(Error::NETWORK_ERROR);
		read_handler->tcp_error_handler("NETWORK_ERROR");
		stop();
		return;
	      }
	    if (!queue.empty())
	      queue_send();
	  }
      }

      void queue_recv(PacketFrom *tcpfrom)
      {
	OPENVPN_LOG_TCPLINK_VERBOSE("TCPLink::queue_recv");
	if (!tcpfrom)
	  tcpfrom = new PacketFrom();
	frame_context.prepare(tcpfrom->buf);
	socket.async_receive(frame_context.mutable_buffers_1(tcpfrom->buf),
			     asio_dispatch_read(&Link::handle_recv, this, tcpfrom));
      }

      void handle_recv(PacketFrom *tcpfrom, const boost::system::error_code& error, const size_t bytes_recvd)
      {
	OPENVPN_LOG_TCPLINK_VERBOSE("TCPLink::handle_recv: " << error.message());
	PacketFrom::SPtr pfp(tcpfrom);
	if (!halt)
	  {
	    if (!error)
	      {
		OPENVPN_LOG_TCPLINK_VERBOSE("TCP recv size=" << bytes_recvd);
		stats->inc_stat(SessionStats::BYTES_IN, bytes_recvd);
		pfp->buf.set_size(bytes_recvd);

		BufferAllocated pkt;
		while (pfp->buf.size())
		  {
		    pktstream.put(pfp->buf, frame_context);
		    if (pktstream.ready())
		      {
			pktstream.get(pkt);
			read_handler->tcp_read_handler(pkt);
		      }
		  }
		if (!pfp->buf.allocated() && pkt.allocated()) // recycle pkt allocated buffer
		  pfp->buf.move(pkt);
		queue_recv(pfp.release()); // reuse PacketFrom object
	      }
	    else
	      {
		OPENVPN_LOG_TCPLINK_ERROR("TCP recv error: " << error.message());
		stats->error(Error::NETWORK_ERROR);
		read_handler->tcp_error_handler("NETWORK_ERROR");
		stop();
	      }
	  }
      }

      boost::asio::ip::tcp::socket& socket;
      bool halt;
      ReadHandler read_handler;
      Frame::Ptr frame;
      const Frame::Context& frame_context;
      SessionStats::Ptr stats;
      const size_t send_queue_max_size;
      const size_t free_list_max_size;
      Queue queue;      // send queue
      Queue free_list;  // recycled free buffers for send queue
      PacketStream pktstream;
    };
  }
} // namespace openvpn

#endif
