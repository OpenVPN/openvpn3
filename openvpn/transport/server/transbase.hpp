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

// Abstract base classes for server transport objects that implement UDP, TCP,
// HTTP Proxy, etc.

#ifndef OPENVPN_TRANSPORT_SERVER_TRANSBASE_H
#define OPENVPN_TRANSPORT_SERVER_TRANSBASE_H

#include <string>

#include <boost/asio.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn {

  // Base class for server transport object.
  class TransportServer : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<TransportServer> Ptr;

    virtual void start() = 0;
    virtual void stop() = 0;
    virtual std::string local_endpoint_info() const = 0;
  };

  // Base class for parent of server transport object, used by server transport
  // objects to communicate status info to TransportServer owner.
  struct TransportServerParent
  {
  };

  // Factory for server transport object.
  class TransportServerFactory : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<TransportServerFactory> Ptr;

    virtual TransportServer::Ptr new_server_obj(boost::asio::io_service& io_service,
						TransportServerParent& parent) = 0;
  };

  // Abstract base class for the per-client-instance state of the TransportServer.
  // Each client instance uses this class to send data to the transport layer.
  // This object is considered the "parent" of a ClientInstanceBase object, and
  // is passed to new ClientInstanceBase objects via the start method.
  class TransportClientInstance
  {
  public:
    virtual bool defined() const = 0;
    virtual void stop() = 0;

    virtual bool transport_send_const(const Buffer& buf) = 0;
    virtual bool transport_send(BufferAllocated& buf) = 0;

    virtual const std::string& info() const = 0;
  };

} // namespace openvpn

#endif 
