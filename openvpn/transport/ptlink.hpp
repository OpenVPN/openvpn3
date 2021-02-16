//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2020 OpenVPN Inc.
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

// Base class for PluggableTransport links.

#ifndef OPENVPN_TRANSPORT_PTLINK_H
#define OPENVPN_TRANSPORT_PTLINK_H

#include <deque>
#include <utility> // for std::move
#include <memory>

#include <openvpn/io/io.hpp>

#include <openvpn/common/size.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/error/excode.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/transport/pktstream.hpp>
#include <openvpn/transport/mutate.hpp>

#include <openvpn/transport/client/pluggable/pt.hpp>

#ifdef OPENVPN_GREMLIN
#include <openvpn/transport/gremlin.hpp>
#endif

#if defined(OPENVPN_DEBUG_PTLINK) && OPENVPN_DEBUG_PTLINK >= 1
#define OPENVPN_LOG_PTLINK_ERROR(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_PTLINK_ERROR(x)
#endif

#if defined(OPENVPN_DEBUG_PTLINK) && OPENVPN_DEBUG_PTLINK >= 3
#define OPENVPN_LOG_PTLINK_VERBOSE(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_PTLINK_VERBOSE(x)
#endif

namespace openvpn {
  namespace PluggableTransports {

    struct PacketFrom
    {
      typedef std::unique_ptr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    template <typename ReadHandler>
    class LinkImpl : public RC<thread_unsafe_refcount>
    {
      typedef std::deque<BufferPtr> Queue;

    public:
      typedef openvpn_io::ip::tcp protocol;
      typedef RCPtr<LinkImpl<ReadHandler>> Ptr;

      void set_mutate(const TransportMutateStream::Ptr& mutate_arg)
      {
	mutate = mutate_arg;
      }

      bool send_queue_empty() const
      {
	return send_queue_size() == 0;
      }

      void inject(const Buffer& src)
      {
	const size_t size = src.size();
	OPENVPN_LOG_PTLINK_VERBOSE("PT inject size=" << size);
	if (size)
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
	if (!halt)
	  queue_recv(nullptr);
      }

      void stop()
      {
	halt = true;
#ifdef OPENVPN_GREMLIN
	if (gremlin)
	  gremlin->stop();
#endif
      }

      void reset_align_adjust(const size_t align_adjust)
      {
	frame_context.reset_align_adjust(align_adjust + 2);
      }

      unsigned int send_queue_size() const
      {
	return queue.size()
#ifdef OPENVPN_GREMLIN
	  + (gremlin ? gremlin->send_size() : 0)
#endif
	  ;
      }

      bool send(BufferAllocated& b)
      {
	if (halt)
	  return false;

	if (send_queue_max_size && send_queue_size() >= send_queue_max_size)
	  {
	    stats->error(Error::PT_OVERFLOW);
	    read_handler->pt_error_handler("PT_OVERFLOW");
	    stop();
	    return false;
	  }

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
	if (mutate)
	  mutate->pre_send(*buf);
#ifdef OPENVPN_GREMLIN
	if (gremlin)
	  gremlin_queue_send_buffer(buf);
	else
#endif
	queue_send_buffer(buf);
	return true;
      }

      void queue_recv(PacketFrom *ptfrom)
      {
	OPENVPN_LOG_PTLINK_VERBOSE("Link::queue_recv");
	if (!ptfrom)
	  ptfrom = new PacketFrom();
	frame_context.prepare(ptfrom->buf);

	async_recv(frame_context.mutable_buffer_clamp(ptfrom->buf),
			     [self=Ptr(this), ptfrom=PacketFrom::SPtr(ptfrom)](const Error::Type error, const size_t bytes_recvd) mutable
			     {
			       OPENVPN_ASYNC_HANDLER;
			       try
			       {
			         self->handle_recv(std::move(ptfrom), error, bytes_recvd);
			       }
			       catch (const std::exception& e)
			       {
			         Error::Type err = Error::PT_SIZE_ERROR;
				 const char *msg = "PT_SIZE_ERROR";
			         // if exception is an ExceptionCode, translate the code
				 // to return status string
				 {
				   const ExceptionCode *ec = dynamic_cast<const ExceptionCode *>(&e);
				   if (ec && ec->code_defined())
				   {
				     err = ec->code();
				     msg = ec->what();
				   }
				 }

			         OPENVPN_LOG_PTLINK_ERROR("PT packet extract exception: " << e.what());
				 self->stats->error(err);
				 self->read_handler->pt_error_handler(msg);
				 self->stop();
			       }
			     });
      }

      LinkImpl(openvpn_io::io_context& io_context_arg,
	     ReadHandler read_handler_arg,
	     openvpn::PluggableTransports::Connection::Ptr connection_arg,
	     const size_t send_queue_max_size_arg, // 0 to disable
	     const size_t free_list_max_size_arg,
	     const Frame::Context& frame_context_arg,
	     const SessionStats::Ptr& stats_arg)
	: io_context(io_context_arg),
	  connection(connection_arg),
	  halt(false),
	  read_handler(read_handler_arg),
	  frame_context(frame_context_arg),
	  stats(stats_arg),
	  send_queue_max_size(send_queue_max_size_arg),
	  free_list_max_size(free_list_max_size_arg)
      {
      }

    protected:
#ifdef OPENVPN_GREMLIN
      void gremlin_config(const Gremlin::Config::Ptr& config)
      {
	if (config)
	  gremlin.reset(new Gremlin::SendRecvQueue(socket.get_executor().context(), config, true));
      }
#endif

      LinkImpl() { stop(); }

      template <typename Handler>
      void async_recv(openvpn_io::mutable_buffer mut_buf, Handler&& completion)
      {
	// capture io_context and connection to avoid capturing self. This assumes that completion captures a reference-counted version of self.
	openvpn_io::io_context& io_context = this->io_context;
	auto connection = this->connection;
	// post to do an async recv, then post ot come back to the "main" thread.
	openvpn_io::post([&io_context, connection, mut_buf, completion=std::move(completion)]() mutable {
	  Error::Type error_code = Error::SUCCESS;
	  size_t bytes_recvd = 0;
	  try
	  {
	    bytes_recvd = connection->receive(mut_buf);
	  }
	  catch (const std::exception& e)
	  {
	      error_code = Error::NETWORK_RECV_ERROR;
	      const ExceptionCode *ec = dynamic_cast<const ExceptionCode *>(&e);
	      if (ec && ec->code_defined())
		error_code = ec->code();
	  }

	  openvpn_io::post(io_context, [error_code, bytes_recvd, completion=std::move(completion)]() mutable {
	    completion(error_code, bytes_recvd);
	  });
	});
      }

      template <typename Handler>
      void async_send(openvpn_io::const_buffer buf, Handler&& completion)
      {
	// capture io_context and connection to avoid capturing self. This assumes that completion captures a reference-counted version of self.
	openvpn_io::io_context& io_context = this->io_context;
	auto connection = this->connection;
	// post to do an async send, then post ot come back to the "main" thread.
	openvpn_io::post([&io_context, connection, buf, completion=std::move(completion)]() {
	  Error::Type error_code = Error::SUCCESS;
	  size_t bytes_sent = 0;
	  try
	  {
	    bytes_sent = connection->send(buf);
	  }
	  catch (const std::exception& e)
	  {
	      error_code = Error::NETWORK_SEND_ERROR;
	      const ExceptionCode *ec = dynamic_cast<const ExceptionCode *>(&e);
	      if (ec && ec->code_defined())
		error_code = ec->code();
	  }

	  openvpn_io::post(io_context, [error_code, bytes_sent, completion=std::move(completion)]() {
	    completion(error_code, bytes_sent);
	  });
	});
      }

      void queue_send_buffer(BufferPtr& buf)
      {
	queue.push_back(std::move(buf));
	if (queue.size() == 1) // send operation not currently active?
	  queue_send();
      }

      void queue_send()
      {
	BufferAllocated& buf = *queue.front();
	async_send(buf.const_buffer_clamp(),
			  [self=Ptr(this)](const Error::Type error_code, const size_t bytes_sent)
			  {
			    OPENVPN_ASYNC_HANDLER;
			    self->handle_send(error_code, bytes_sent);
			  });
      }

      void handle_send(const Error::Type error, const size_t bytes_sent)
      {
	if (!halt)
	  {
	    if (!error)
	      {
		OPENVPN_LOG_PTLINK_VERBOSE("PT send size=" << bytes_sent);
		stats->inc_stat(SessionStats::BYTES_OUT, bytes_sent);
		stats->inc_stat(SessionStats::PACKETS_OUT, 1);

		BufferPtr buf = queue.front();
		if (bytes_sent == buf->size())
		  {
		    queue.pop_front();
		    if (free_list.size() < free_list_max_size)
		      {
			buf->reset_content();
			free_list.push_back(std::move(buf)); // recycle the buffer for later use
		      }
		  }
		else if (bytes_sent < buf->size())
		  buf->advance(bytes_sent);
		else
		  {
		    stats->error(Error::PT_OVERFLOW);
		    read_handler->pt_error_handler("PT_OVERFLOW"); // error sent more bytes than we asked for
		    stop();
		    return;
		  }
	      }
	    else
	      {
		OPENVPN_LOG_PTLINK_ERROR("PT send error");
		stats->error(Error::NETWORK_SEND_ERROR);
		read_handler->pt_error_handler("NETWORK_SEND_ERROR");
		stop();
		return;
	      }
	    if (!queue.empty())
	      queue_send();
	    else
	      pt_write_queue_needs_send();
	  }
      }

      void recv_buffer(PacketFrom::SPtr& pfp, const size_t bytes_recvd)
      {
	bool requeue = true;
	OPENVPN_LOG_PTLINK_VERBOSE("PT recv size=" << bytes_recvd);

	pfp->buf.set_size(bytes_recvd);
	requeue = process_recv_buffer(pfp->buf);
	if (!halt && requeue)
	  queue_recv(pfp.release()); // reuse PacketFrom object
      }

      bool process_recv_buffer(BufferAllocated& buf)
      {
	bool requeue = true;
	OPENVPN_LOG_PTLINK_VERBOSE("PT process_recv_buffer size=" << buf.size());


	try {
	  BufferAllocated pkt;
	  requeue = put_pktstream(buf, pkt);
	  if (!buf.allocated() && pkt.allocated()) // recycle pkt allocated buffer
	    buf.move(pkt);
	}
	catch (const std::exception& e)
	{
	  OPENVPN_LOG_PTLINK_ERROR("packet extract error: " << e.what());
	  stats->error(Error::PT_SIZE_ERROR);
	  read_handler->pt_error_handler("PT_SIZE_ERROR");
	  stop();
	  return false;
	}

	return requeue;
      }

      void handle_recv(PacketFrom::SPtr pfp, Error::Type error, const int bytes_recvd)
      {
	OPENVPN_LOG_PTLINK_VERBOSE("Link::handle_recv: error_code=" << error_code);
	if (!halt)
	{
	  if (!error)
	  {
	    recv_buffer(pfp, bytes_recvd);
	  }
	  else if (error == Error::NETWORK_EOF_ERROR)
	  {
	    OPENVPN_LOG_PTLINK_ERROR("PT recv EOF");
	    read_handler->pt_eof_handler();
	  }
	  else
	  {
	    OPENVPN_LOG_PTLINK_ERROR("PT recv error: error_code=" << error);
	    stats->error(Error::NETWORK_RECV_ERROR);
	    read_handler->pt_error_handler("NETWORK_RECV_ERROR");
	    stop();
	  }
	}
      }

      bool put_pktstream(BufferAllocated& buf, BufferAllocated& pkt)
      {
	bool requeue = true;
	stats->inc_stat(SessionStats::BYTES_IN, buf.size());
	stats->inc_stat(SessionStats::PACKETS_IN, 1);
	if (mutate)
	  mutate->post_recv(buf);
	while (buf.size())
	  {
	    pktstream.put(buf, frame_context);
	    if (pktstream.ready())
	      {
		pktstream.get(pkt);
#ifdef OPENVPN_GREMLIN
		if (gremlin)
		  requeue = gremlin_recv(pkt);
		else
#endif
		requeue = read_handler->pt_read_handler(pkt);
	      }
	  }
	return requeue;
      }

#ifdef OPENVPN_GREMLIN
      void gremlin_queue_send_buffer(BufferPtr& buf)
      {
	gremlin->send_queue([self=Ptr(this), buf=std::move(buf)]() mutable {
	    if (!self->halt)
	      {
		self->queue_send_buffer(buf);
	      }
	  });
      }

      bool gremlin_recv(BufferAllocated& buf)
      {
	gremlin->recv_queue([self=Ptr(this), buf=std::move(buf)]() mutable {
	    if (!self->halt)
	      {
		const bool requeue = self->read_handler->pt_read_handler(buf);
		if (requeue)
		  self->queue_recv(nullptr);
	      }
	  });
	return false;
      }
#endif

      void pt_write_queue_needs_send()
      {
	read_handler->pt_write_queue_needs_send();
      }

      openvpn_io::io_context& io_context;
      openvpn::PluggableTransports::Connection::Ptr connection;

      bool halt;
      ReadHandler read_handler;
      Frame::Context frame_context;
      SessionStats::Ptr stats;
      const size_t send_queue_max_size;
      const size_t free_list_max_size;
      Queue queue;      // send queue
      Queue free_list;  // recycled free buffers for send queue
      PacketStream pktstream;
      TransportMutateStream::Ptr mutate;

#ifdef OPENVPN_GREMLIN
      std::unique_ptr<Gremlin::SendRecvQueue> gremlin;
#endif
    };
  }
} // namespace openvpn

#endif
