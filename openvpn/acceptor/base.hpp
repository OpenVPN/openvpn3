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

// multi-protocol acceptor classes that handle the protocol-specific
// details of accepting client connections.

#ifndef OPENVPN_ACCEPTOR_BASE_H
#define OPENVPN_ACCEPTOR_BASE_H

#include <vector>
#include <utility>

#include <asio.hpp>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/asiopolysock.hpp>

namespace openvpn {
  namespace Acceptor {

    struct ListenerBase : public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<ListenerBase> Ptr;

      virtual void handle_accept(AsioPolySock::Base::Ptr sock, const asio::error_code& error) = 0;
    };

    struct Base : public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Base> Ptr;

      virtual void async_accept(ListenerBase* listener,
				const size_t acceptor_index,
				asio::io_context& io_context) = 0;
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
