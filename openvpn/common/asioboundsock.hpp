//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

// Asio TCP socket that can be configured so that open() method
// always prebinds the socket to a given local address.  Useful
// for TCP clients.

#ifndef OPENVPN_COMMON_ASIOBOUNDSOCK_H
#define OPENVPN_COMMON_ASIOBOUNDSOCK_H

#include <boost/asio.hpp>

#include <openvpn/addr/ip.hpp>

namespace openvpn {
  namespace AsioBoundSocket {

    typedef boost::asio::stream_socket_service<boost::asio::ip::tcp> SocketServiceBase;

    struct SocketService : public SocketServiceBase
    {
      struct implementation_type : public SocketServiceBase::implementation_type
      {
	IP::Addr bind_local_addr;
      };

      explicit SocketService(boost::asio::io_service& io_service)
	: SocketServiceBase(io_service)
      {
      }

      static boost::asio::detail::service_id<SocketService> id; // register the service

      // Override the open method so we can bind immediately after open.
      boost::system::error_code open(implementation_type& impl,
				     const protocol_type& protocol,
				     boost::system::error_code& ec)
      {
	ec = SocketServiceBase::open(impl, protocol, ec);
	if (ec)
	  return ec;
	if (impl.bind_local_addr.defined())
	  {
	    ec = set_option(impl, boost::asio::socket_base::reuse_address(true), ec);
	    if (ec)
	      return ec;
	    ec = bind(impl,
		      boost::asio::ip::tcp::endpoint(impl.bind_local_addr.to_asio(), 0), // port 0 -- kernel will choose port
		      ec);
	  }
	return ec;
      }

    };

    typedef boost::asio::basic_stream_socket<boost::asio::ip::tcp, SocketService> SocketBase;

    struct Socket : public SocketBase
    {
      explicit Socket(boost::asio::io_service& io_service)
	: SocketBase(io_service)
      {
      }

      void bind_local(const IP::Addr& addr)
      {
	this->get_implementation().bind_local_addr = addr;
      }
    };

  }
}

#endif
