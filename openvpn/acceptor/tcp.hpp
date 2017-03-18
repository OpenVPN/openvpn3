//
//  tcp.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.
//

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
