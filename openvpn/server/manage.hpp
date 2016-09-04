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

// Server-side client manager

#ifndef OPENVPN_SERVER_MANAGE_H
#define OPENVPN_SERVER_MANAGE_H

#include <string>
#include <vector>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/tun/server/tunbase.hpp>
#include <openvpn/addr/route.hpp>
#include <openvpn/auth/authcreds.hpp>
#include <openvpn/ssl/proto.hpp>
#include <openvpn/server/servhalt.hpp>
#include <openvpn/server/peerstats.hpp>
#include <openvpn/server/peeraddr.hpp>
#include <openvpn/auth/authcert.hpp>

namespace openvpn {
  // Base class for the per-client-instance state of the ManServer.
  // Each client instance uses this class to send data to the man layer.
  struct ManClientInstanceSend : public virtual RC<thread_unsafe_refcount>
  {
    typedef RCPtr<ManClientInstanceSend> Ptr;

    //virtual bool defined() const = 0;
    virtual void stop() = 0;

    virtual void auth_request(const AuthCreds::Ptr& auth_creds,
			      const AuthCert::Ptr& auth_cert,
			      const PeerAddr::Ptr& peer_addr) = 0;
    virtual void push_request(const ProtoContext::Config::Ptr& pconf) = 0;

    // bandwidth stats notification
    virtual void stats_notify(const PeerStats& ps, const bool final) = 0;

    // client float notification
    virtual void float_notify(const PeerAddr::Ptr& addr) = 0;

    // return a JSON string describing connected user
    virtual std::string describe_user() = 0;

    // disconnect
    virtual void disconnect_user(const HaltRestart::Type type,
				 const std::string& reason,
				 const bool tell_client) = 0;

    // send control channel message
    virtual void post_info_user(BufferPtr&& info) = 0;

    // set ACL ID for user
    virtual void set_acl_id(const unsigned int acl_id,
			    const std::string* username,
			    const bool challenge,
			    const bool throw_on_error) = 0;
  };

  // Base class for the client instance receiver.  Note that all
  // client instance receivers (transport, routing, management,
  // etc.) must inherit virtually from RC because the client instance
  // object will inherit from multiple receivers.
  struct ManClientInstanceRecv : public virtual RC<thread_unsafe_refcount>
  {
    typedef RCPtr<ManClientInstanceRecv> Ptr;

    //virtual bool defined() const = 0;
    virtual void stop() = 0;

    virtual void auth_failed(const std::string& reason,
			     const bool tell_client) = 0;

    virtual void push_reply(std::vector<BufferPtr>&& push_msgs,
			    const std::vector<IP::Route>& routes,
			    const unsigned int initial_fwmark) = 0;

    // push a halt or restart message to client
    virtual void push_halt_restart_msg(const HaltRestart::Type type,
				       const std::string& reason,
				       const bool tell_client) = 0;


    // send control channel message
    virtual void post_info(BufferPtr&& info) = 0;

    // set fwmark value in client instance
    virtual void set_fwmark(const unsigned int fwmark) = 0;

    // get client bandwidth stats
    virtual PeerStats stats_poll() = 0;
  };

  struct ManClientInstanceFactory : public RC<thread_unsafe_refcount>
  {
    typedef RCPtr<ManClientInstanceFactory> Ptr;

    virtual void start() = 0;

    virtual ManClientInstanceSend::Ptr new_obj(ManClientInstanceRecv* instance) = 0;
  };

}

#endif
