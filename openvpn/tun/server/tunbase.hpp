//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

// Abstract base classes for server tun objects

#ifndef OPENVPN_TUN_SERVER_TUNBASE_H
#define OPENVPN_TUN_SERVER_TUNBASE_H

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/function.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/server/servhalt.hpp>

namespace openvpn::TunClientInstance {

typedef Function<void(int fd)> PostCloseFunc;

// A native reference to a client instance
struct NativeHandle
{
    NativeHandle()
    {
    }

    NativeHandle(const int fd_arg, const int peer_id_arg)
        : fd(fd_arg),
          peer_id(peer_id_arg)
    {
    }

    bool fd_defined() const
    {
        return fd >= 0;
    }

    bool defined() const
    {
        return fd >= 0 && peer_id >= 0;
    }

    int fd = -1;
    int peer_id = -1;
};

// Base class for the client instance receiver.  Note that all
// client instance receivers (transport, routing, management,
// etc.) must inherit virtually from RC because the client instance
// object will inherit from multiple receivers.
struct Recv : public virtual RC<thread_unsafe_refcount>
{
    typedef RCPtr<Recv> Ptr;

    // virtual bool defined() const = 0;
    virtual void stop() = 0;

    // Called with IP packets from tun layer.
    virtual void tun_recv(BufferAllocated &buf) = 0;

    // clang-format off
    // push a halt or restart message to client
    virtual void push_halt_restart_msg(const HaltRestart::Type type,
                                       const std::string &reason,
                                       const std::string &client_reason) = 0;
    // clang-format on
};

// Base class for the per-client-instance state of the TunServer.
// Each client instance uses this class to send data to the tun layer.
struct Send : public virtual RC<thread_unsafe_refcount>
{
    typedef RCPtr<Send> Ptr;

    // virtual bool defined() const = 0;
    virtual void stop() = 0;

    virtual bool tun_send_const(const Buffer &buf) = 0;
    virtual bool tun_send(BufferAllocated &buf) = 0;

    // get the native handle for tun/peer
    virtual NativeHandle tun_native_handle() = 0;

    // set up relay to target
    virtual void relay(const IP::Addr &target, const int port) = 0;

    virtual const std::string &tun_info() const = 0;
};

// Factory for server tun object.
struct Factory : public RC<thread_unsafe_refcount>
{
    typedef RCPtr<Factory> Ptr;

    virtual Send::Ptr new_tun_obj(Recv *parent) = 0;
};

} // namespace openvpn::TunClientInstance

#endif
