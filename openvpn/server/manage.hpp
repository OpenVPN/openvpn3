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

// Server-side client manager

#ifndef OPENVPN_SERVER_MANAGE_H
#define OPENVPN_SERVER_MANAGE_H

#include <string>
#include <vector>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/tun/server/tunbase.hpp>
#include <openvpn/addr/route.hpp>
#include <openvpn/auth/authcreds.hpp>

namespace openvpn {
  // Base class for the per-client-instance state of the ManServer.
  // Each client instance uses this class to send data to the man layer.
  struct ManClientInstanceSend : public virtual RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<ManClientInstanceSend> Ptr;

    //virtual bool defined() const = 0;
    virtual void stop() = 0;

    virtual void auth_request(const AuthCreds::Ptr& auth_creds) = 0;
    virtual void push_request() = 0;
  };

  // Base class for the client instance receiver.  Note that all
  // client instance receivers (transport, routing, management,
  // etc.) must inherit virtually from RC because the client instance
  // object will inherit from multiple receivers.
  struct ManClientInstanceRecv : public virtual RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<ManClientInstanceRecv> Ptr;

    //virtual bool defined() const = 0;
    virtual void stop() = 0;

    virtual void auth_failed(const std::string& client_reason) = 0;
    virtual void push_reply(BufferPtr& push_data,
			    const std::vector<IP::Route>& routes) = 0;
  };

  struct ManClientInstanceFactory : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<ManClientInstanceFactory> Ptr;

    virtual void start() = 0;

    virtual ManClientInstanceSend::Ptr new_obj(ManClientInstanceRecv* instance) = 0;
  };

}

#endif
