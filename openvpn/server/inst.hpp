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

// Client instance base class on server

#ifndef OPENVPN_SERVER_INST_H
#define OPENVPN_SERVER_INST_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>

namespace openvpn {

  class TransportClientInstance;

  class ClientInstanceBase : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ClientInstanceBase> Ptr;

    virtual bool defined() const = 0;

    virtual void start(TransportClientInstance* tci) = 0;
    virtual void stop() = 0;

    // Called with OpenVPN-encapsulated packets from transport layer.
    virtual void transport_recv(BufferAllocated& buf) = 0;

    // Called with cleartext IP packets from routing layer.
    virtual void tun_recv(BufferAllocated& buf) = 0;

    // Called with control channel push commands to
    // newly connected client by manager layer.
    virtual void push(BufferPtr& buf, bool auth_status) = 0;
  };

  class ClientInstanceFactory : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ClientInstanceFactory> Ptr;

    virtual ClientInstanceBase::Ptr new_client_instance() = 0;
    virtual bool validate_initial_packet(const Buffer& net_buf) = 0;
  };

}

#endif
