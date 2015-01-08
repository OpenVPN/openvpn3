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

// Abstract base classes for server tun objects

#ifndef OPENVPN_TUN_SERVER_TUNBASE_H
#define OPENVPN_TUN_SERVER_TUNBASE_H

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/server/servhalt.hpp>

namespace openvpn {

  // Base class for the client instance receiver.  Note that all
  // client instance receivers (transport, routing, management,
  // etc.) must inherit virtually from RC because the client instance
  // object will inherit from multiple receivers.
  struct TunClientInstanceRecv : public virtual RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunClientInstanceRecv> Ptr;

    //virtual bool defined() const = 0;
    virtual void stop() = 0;

    // Called with IP packets from tun layer.
    virtual void tun_recv(BufferAllocated& buf) = 0;

    // push a halt or restart message to client
    virtual void push_halt_restart_msg(const HaltRestart::Type type,
				       const std::string& reason,
				       const bool tell_client) = 0;
  };

  // Base class for the per-client-instance state of the TunServer.
  // Each client instance uses this class to send data to the tun layer.
  struct TunClientInstanceSend : public virtual RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunClientInstanceSend> Ptr;

    //virtual bool defined() const = 0;
    virtual void stop() = 0;

    virtual bool tun_send_const(const Buffer& buf) = 0;
    virtual bool tun_send(BufferAllocated& buf) = 0;

    // add routes
    virtual void add_routes(const std::vector<IP::Route>& rtvec) = 0;

    virtual const std::string& tun_info() const = 0;
  };

  // Factory for server tun object.
  struct TunClientInstanceFactory : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunClientInstanceFactory> Ptr;

    virtual TunClientInstanceSend::Ptr new_obj(TunClientInstanceRecv* parent) = 0;
  };

} // namespace openvpn

#endif
