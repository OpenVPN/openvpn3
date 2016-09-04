//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_ACCEPTOR_TCP_H
#define OPENVPN_ACCEPTOR_TCP_H

#include <openvpn/acceptor/base.hpp>

namespace openvpn {
  namespace Acceptor {

    struct TCP : public Base
    {
      typedef RCPtr<TCP> Ptr;

      TCP(asio::io_context& io_context)
	: acceptor(io_context)
      {
      }

      virtual void async_accept(ListenerBase* listener,
				const size_t acceptor_index,
				asio::io_context& io_context) override
      {
	AsioPolySock::TCP::Ptr sock(new AsioPolySock::TCP(io_context, acceptor_index));
	acceptor.async_accept(sock->socket, [listener=ListenerBase::Ptr(listener), sock](const asio::error_code& error)
			      {
				listener->handle_accept(sock, error);
			      });
      }

      virtual void close() override
      {
	acceptor.close();
      }

      void set_socket_options()
      {
#if defined(OPENVPN_PLATFORM_WIN)
	// set Windows socket flags
	acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true));
#else
	// set Unix socket flags
	{
	  const int fd = acceptor.native_handle();
	  SockOpt::reuseport(fd);
	  SockOpt::reuseaddr(fd);
	  SockOpt::set_cloexec(fd);
	}
#endif
      }

      asio::ip::tcp::endpoint local_endpoint;
      asio::ip::tcp::acceptor acceptor;
    };

  }
}

#endif
