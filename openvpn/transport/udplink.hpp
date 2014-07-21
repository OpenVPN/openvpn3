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

// Low-level UDP transport object.

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
	   const Frame::Context& frame_context_arg,
	   const SessionStats::Ptr& stats_arg)
	: socket(socket_arg),
	  halt(false),
	  read_handler(read_handler_arg),
	  frame_context(frame_context_arg),
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
	      stats->inc_stat(SessionStats::PACKETS_OUT, 1);
	      if (wrote == buf.size())
		return true;
	      else
		{
		  OPENVPN_LOG_UDPLINK_ERROR("UDP partial send error");
		  stats->error(Error::NETWORK_SEND_ERROR);
		  return false;
		}
	    }
	    catch (boost::system::system_error& e)
	      {
		OPENVPN_LOG_UDPLINK_ERROR("UDP send error: " << e.what());
		stats->error(Error::NETWORK_SEND_ERROR);
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
		    stats->inc_stat(SessionStats::PACKETS_IN, 1);
		    read_handler->udp_read_handler(pfp);
		  }
		else
		  {
		    OPENVPN_LOG_UDPLINK_ERROR("UDP recv error: " << error.message());
		    stats->error(Error::NETWORK_RECV_ERROR);
		  }
	      }
	    queue_read(pfp.release()); // reuse PacketFrom object if still available
	  }
      }

      boost::asio::ip::udp::socket& socket;
      bool halt;
      ReadHandler read_handler;
      const Frame::Context frame_context;
      SessionStats::Ptr stats;
    };
  }
} // namespace openvpn

#endif
