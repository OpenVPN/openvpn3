//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2026- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

/**
 * @file
 * @brief A null tun-layer backend for the server, discarding all payload.
 *
 * @details
 * Implements the @c TunClientInstance seam (`openvpn/tun/server/tunbase.hpp`)
 * with a backend that accepts and drops every packet handed to it. It exists so
 * a server can be stood up and driven through a full control-channel lifecycle
 * (handshake, push, keepalive, rekey, disconnect) with no tun device, no
 * routing, and no privilege, which isolates control-plane behaviour from
 * data-plane behaviour when bringing a server up or reproducing a protocol bug.
 *
 * This is deliberately not a data path. A real backend programs a data plane
 * (kernel DCO, or the batched userspace engine) via
 * @c TransportClientInstance::Recv::override_dc_factory and
 * @c override_tun, after which payload never traverses @c ServerProto::Session
 * at all. Note that @c ServerProto::Session itself carries no userspace data
 * path: its @c tun_recv() is a stub. Anything beyond control-channel work needs
 * one of those real backends.
 */

#ifndef OPENVPN_SERVER_TUNSINK_H
#define OPENVPN_SERVER_TUNSINK_H

#include <string>

#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/tun/server/tunbase.hpp>

namespace openvpn::TunSink {

/**
 * @brief Per-client tun-layer object that discards everything sent to it.
 *
 * @details
 * One instance exists per connected client, handed to the protocol session as
 * its @c TunLink::send. Every send path reports success so that the protocol
 * layer observes a healthy, non-backpressuring tun layer; the payload is
 * dropped. Holds no file descriptor and no peer identity, so
 * @c tun_native_handle() returns an undefined handle.
 */
class TunSend : public TunClientInstance::Send
{
  public:
    using Ptr = RCPtr<TunSend>;

    /**
     * @brief Construct the per-client null tun object.
     * @param parent The session this instance was created for; borrowed.
     */
    explicit TunSend(TunClientInstance::Recv *parent)
        : parent_(parent), info_("NULL_TUN")
    {
    }

    /**
     * @brief Drop the back-pointer to the owning session.
     * @details Idempotent, since teardown paths may call this more than once.
     *  Does not touch @c PeerRoutes: the management instance owns both halves
     *  of the assign/release pair (see peerroutes.hpp).
     */
    void stop() override
    {
        parent_ = nullptr;
    }

    /**
     * @brief Accept and discard a const cleartext IP packet.
     * @param buf The packet, unmodified.
     * @return Always @c true, reporting a successful send.
     */
    bool tun_send_const([[maybe_unused]] const Buffer &buf) override
    {
        return true;
    }

    /**
     * @brief Accept and discard a mutable cleartext IP packet.
     * @param buf The packet. Emptied so a caller that inspects the buffer
     *  afterwards sees it consumed rather than untouched.
     * @return Always @c true, reporting a successful send.
     */
    bool tun_send(BufferAllocated &buf) override
    {
        buf.reset_size();
        return true;
    }

    /**
     * @brief Report that no native tun/peer handle exists.
     * @return A default-constructed handle, for which @c defined() is false.
     */
    TunClientInstance::NativeHandle tun_native_handle() override
    {
        return TunClientInstance::NativeHandle();
    }

    /**
     * @brief Relay setup, which this backend does not support.
     * @param target Ignored relay target address.
     * @param port Ignored relay target port.
     */
    void relay([[maybe_unused]] const IP::Addr &target, [[maybe_unused]] const int port) override
    {
    }

    /**
     * @brief Human-readable description of this tun layer, for logging.
     * @return A stable string identifying the backend as the null tun.
     */
    const std::string &tun_info() const override
    {
        return info_;
    }

  private:
    TunClientInstance::Recv *parent_;
    std::string info_;
};

/**
 * @brief TunFactory producing one @c TunSend per connected client.
 *
 * @details
 * Held by @c ServerProto::Factory as its @c tun_factory. Stateless, so a
 * single instance is shared across every client the server accepts.
 */
class TunFactory : public TunClientInstance::Factory
{
  public:
    using Ptr = RCPtr<TunFactory>;

    /**
     * @brief Create the tun-layer object for one client session.
     * @param parent The protocol session requesting a tun layer. Borrowed, not
     *  owned; the caller guarantees it outlives the returned object's use.
     * @return A new @c TunSend bound to @p parent.
     */
    TunClientInstance::Send::Ptr new_tun_obj(TunClientInstance::Recv *parent) override
    {
        return TunClientInstance::Send::Ptr(new TunSend(parent));
    }
};

} // namespace openvpn::TunSink

#endif
