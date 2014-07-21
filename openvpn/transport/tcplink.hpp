//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Low-level TCP transport object.

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

    template <typename ReadHandler, bool RAW_MODE_ONLY>
    class Link : public RC<thread_unsafe_refcount>
    {
      typedef std::deque<BufferPtr> Queue;

    public:
      typedef boost::intrusive_ptr<Link> Ptr;

      Link(ReadHandler read_handler_arg,
	   boost::asio::ip::tcp::socket& socket_arg,
	   const size_t send_queue_max_size_arg,
	   const size_t free_list_max_size_arg,
	   const Frame::Context& frame_context_arg,
	   const SessionStats::Ptr& stats_arg)
	: socket(socket_arg),
	  halt(false),
	  read_handler(read_handler_arg),
	  frame_context(frame_context_arg),
	  stats(stats_arg),
	  send_queue_max_size(send_queue_max_size_arg),
	  free_list_max_size(free_list_max_size_arg)
      {
	set_raw_mode(false);
      }

      // In raw mode, data is sent and received without any special encapsulation.
      // In non-raw mode, data is packetized by prepending a 16-bit length word
      // onto each packet.  The OpenVPN protocol runs in non-raw mode, while other
      // TCP protocols such as HTTP or HTTPS would run in raw mode.
      // This method is a no-op if RAW_MODE_ONLY is true.
      void set_raw_mode(const bool mode)
      {
	if (RAW_MODE_ONLY)
	  raw_mode = true;
	else
	  raw_mode = mode;
      }

      bool is_raw_mode() const {
	if (RAW_MODE_ONLY)
	  return true;
	else
	  return raw_mode;
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
		if (!is_raw_mode())
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

      void inject(const BufferAllocated& src)
      {
	const size_t size = src.size();
	OPENVPN_LOG_TCPLINK_VERBOSE("TCP inject size=" << size);
       	if (size && !RAW_MODE_ONLY)
	  {
	    BufferAllocated buf;
	    frame_context.prepare(buf);
	    buf.write(src.c_data(), size);
	    BufferAllocated pkt;
	    put_pktstream(buf, pkt);
	  }
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
		OPENVPN_LOG_TCPLINK_VERBOSE("TCP send raw=" << raw_mode << " size=" << bytes_sent);
		stats->inc_stat(SessionStats::BYTES_OUT, bytes_sent);
		stats->inc_stat(SessionStats::PACKETS_OUT, 1);

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
		stats->error(Error::NETWORK_SEND_ERROR);
		read_handler->tcp_error_handler("NETWORK_SEND_ERROR");
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
		OPENVPN_LOG_TCPLINK_VERBOSE("TCP recv raw=" << raw_mode << " size=" << bytes_recvd);
		pfp->buf.set_size(bytes_recvd);
		if (!is_raw_mode())
		  {
		    BufferAllocated pkt;
		    put_pktstream(pfp->buf, pkt);
		    if (!pfp->buf.allocated() && pkt.allocated()) // recycle pkt allocated buffer
		      pfp->buf.move(pkt);
		  }
		else
		  read_handler->tcp_read_handler(pfp->buf);
		queue_recv(pfp.release()); // reuse PacketFrom object
	      }
	    else if (error == boost::asio::error::eof)
	      {
		OPENVPN_LOG_TCPLINK_ERROR("TCP recv EOF");
		read_handler->tcp_eof_handler();
	      }
	    else
	      {
		OPENVPN_LOG_TCPLINK_ERROR("TCP recv error: " << error.message());
		stats->error(Error::NETWORK_RECV_ERROR);
		read_handler->tcp_error_handler("NETWORK_RECV_ERROR");
		stop();
	      }
	  }
      }

      void put_pktstream(BufferAllocated& buf, BufferAllocated& pkt)
      {
	stats->inc_stat(SessionStats::BYTES_IN, buf.size());
	stats->inc_stat(SessionStats::PACKETS_IN, 1);
	while (buf.size())
	  {
	    pktstream.put(buf, frame_context);
	    if (pktstream.ready())
	      {
		pktstream.get(pkt);
		read_handler->tcp_read_handler(pkt);
	      }
	  }
      }

      boost::asio::ip::tcp::socket& socket;
      bool halt;
      bool raw_mode;
      ReadHandler read_handler;
      const Frame::Context frame_context;
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
