//
//  unix.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//  All rights reserved.
//

#ifndef OPENVPN_ACCEPTOR_UNIX_H
#define OPENVPN_ACCEPTOR_UNIX_H

#include <unistd.h>    // for unlink()
#include <sys/stat.h>  // for chmod()

#include <openvpn/acceptor/base.hpp>

namespace openvpn {
  namespace Acceptor {

    struct Unix : public Base
    {
      OPENVPN_EXCEPTION(unix_acceptor_error);

      typedef RCPtr<Unix> Ptr;

      Unix(asio::io_context& io_context)
	: acceptor(io_context)
      {
      }

      virtual void async_accept(ListenerBase* listener,
				const size_t acceptor_index,
				asio::io_context& io_context) override
      {
	AsioPolySock::Unix::Ptr sock(new AsioPolySock::Unix(io_context, acceptor_index));
	acceptor.async_accept(sock->socket, [listener=ListenerBase::Ptr(listener), sock](const asio::error_code& error)
			      {
				listener->handle_accept(sock, error);
			      });
      }

      virtual void close() override
      {
	acceptor.close();
      }

      static void pre_listen(const std::string& socket_path)
      {
	// remove previous socket instance
	::unlink(socket_path.c_str());
      }

      // set socket permissions in filesystem
      static void set_socket_permissions(const std::string& socket_path,
					 const mode_t unix_mode)
      {
	if (unix_mode)
	  {
	    if (::chmod(socket_path.c_str(), unix_mode) < 0)
	      throw unix_acceptor_error("chmod failed on unix socket");
	  }
      }

      asio::local::stream_protocol::endpoint local_endpoint;
      asio::basic_socket_acceptor<asio::local::stream_protocol> acceptor;
    };

  }
}

#endif
