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

#ifndef OPENVPN_TRANSPORT_CLIENT_PT_H
#define OPENVPN_TRANSPORT_CLIENT_PT_H

#include <openvpn/io/io.hpp>
#include <openvpn/common/rc.hpp>

#ifdef OPENVPN_PLUGGABLE_TRANSPORTS

namespace openvpn {
  namespace PluggableTransports {
    struct Connection : public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Connection> Ptr;

      virtual size_t send(const openvpn_io::const_buffer& buffer) = 0;
      virtual size_t receive(const openvpn_io::mutable_buffer& buffer) = 0;
      virtual void close() = 0;
      virtual int native_handle() = 0;
    };

    struct Transport: public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Transport> Ptr;

    public:
      virtual PluggableTransports::Connection::Ptr dial(openvpn_io::ip::tcp::endpoint address) = 0;
    };
  }
}

#endif // OPENVPN_PLUGGABLE_TRANSPORTS

#endif
