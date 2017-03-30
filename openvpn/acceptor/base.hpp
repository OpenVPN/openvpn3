//
//  base.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.
//

// multi-protocol acceptor classes that handle the protocol-specific
// details of accepting client connections.

#ifndef OPENVPN_ACCEPTOR_BASE_H
#define OPENVPN_ACCEPTOR_BASE_H

#include <vector>
#include <utility>

#include <openvpn/io/io.hpp>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/asio/asiopolysock.hpp>

#ifndef OPENVPN_ACCEPTOR_LISTENER_BASE_RC
#define OPENVPN_ACCEPTOR_LISTENER_BASE_RC RC<thread_unsafe_refcount>
#endif

namespace openvpn {
  namespace Acceptor {

    struct ListenerBase : public OPENVPN_ACCEPTOR_LISTENER_BASE_RC
    {
      typedef RCPtr<ListenerBase> Ptr;

      virtual void handle_accept(AsioPolySock::Base::Ptr sock, const openvpn_io::error_code& error) = 0;
    };

    struct Base : public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Base> Ptr;

      virtual void async_accept(ListenerBase* listener,
				const size_t acceptor_index,
				openvpn_io::io_context& io_context) = 0;
      virtual void close() = 0;
    };

    struct Item
    {
      Item(Base::Ptr acceptor_arg,
	   const bool ssl_arg)
	: acceptor(std::move(acceptor_arg)),
	  ssl(ssl_arg)
      {
      }

      Base::Ptr acceptor;
      bool ssl;
    };

    struct Set : public std::vector<Item>
    {
      void close()
      {
	for (auto &i : *this)
	  i.acceptor->close();
      }
    };

  }
}

#endif
