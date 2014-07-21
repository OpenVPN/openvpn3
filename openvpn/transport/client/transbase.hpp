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

// Abstract base classes for client transport objects that implement UDP, TCP,
// HTTP Proxy, etc.

#ifndef OPENVPN_TRANSPORT_CLIENT_TRANSBASE_H
#define OPENVPN_TRANSPORT_CLIENT_TRANSBASE_H

#include <string>

#include <boost/asio.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn {

  // Base class for client transport object.
  struct TransportClient : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TransportClient> Ptr;

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual bool transport_send_const(const Buffer& buf) = 0;
    virtual bool transport_send(BufferAllocated& buf) = 0;
    virtual IP::Addr server_endpoint_addr() const = 0;
    virtual void server_endpoint_info(std::string& host, std::string& port, std::string& proto, std::string& ip_addr) const = 0;
  };

  // Base class for parent of client transport object, used by client transport
  // objects to communicate received data packets, exceptions, and progress
  // notifications.
  struct TransportClientParent
  {
    virtual void transport_recv(BufferAllocated& buf) = 0;
    virtual void transport_error(const Error::Type fatal_err, const std::string& err_text) = 0;
    virtual void proxy_error(const Error::Type fatal_err, const std::string& err_text) = 0;

    // Called just prior to transport layer opening up a socket to addr.
    // Allows the implementation to ensure connectivity for outgoing
    // transport connection to server.
    virtual void ip_hole_punch(const IP::Addr& addr) = 0;

    // progress notifications
    virtual void transport_pre_resolve() = 0;
    virtual void transport_wait_proxy() = 0;
    virtual void transport_wait() = 0;
    virtual void transport_connecting() = 0;
  };

  // Factory for client transport object.
  struct TransportClientFactory : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TransportClientFactory> Ptr;

    virtual TransportClient::Ptr new_client_obj(boost::asio::io_service& io_service,
						TransportClientParent& parent) = 0;
  };

} // namespace openvpn

#endif // OPENVPN_TRANSPORT_CLIENT_TRANSBASE_H
