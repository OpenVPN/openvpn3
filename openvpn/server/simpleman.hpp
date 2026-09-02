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
 * @brief A minimal management/policy layer for the server: accept every client.
 *
 * @details
 * Implements the @c ManClientInstance seam (`openvpn/server/manage.hpp`), which
 * is where a server's policy lives: authentication verdicts, the push reply,
 * per-client stats, and disconnects. @c ServerProto::Session drives it and
 * knows nothing about how the verdict is reached.
 *
 * This implementation approves every client that completes the TLS handshake
 * and pushes a fixed tunnel configuration. It is the smallest thing that lets a
 * stock OpenVPN 2.6 client reach a fully connected state, which makes it the
 * right harness for exercising the control channel end to end without dragging
 * in an authentication backend. **It performs no authentication beyond the TLS
 * layer's own certificate verification and must not be deployed.**
 *
 * Address assignment goes through `PeerRoutes` (peerroutes.hpp): the factory
 * takes a `PeerRoutes::Lease` per client, which holds an address from the pool
 * and its route for as long as the client's `ManSend` lives.
 */

#ifndef OPENVPN_SERVER_SIMPLEMAN_H
#define OPENVPN_SERVER_SIMPLEMAN_H

#include <cstdint>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/jsonlib.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/auth/authcert.hpp>
#include <openvpn/auth/authcreds.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>
#include <openvpn/log/logger.hpp>
#include <openvpn/server/manage.hpp>
#include <openvpn/server/peerroutes.hpp>
#include <openvpn/server/peeraddr.hpp>
#include <openvpn/server/peerstats.hpp>
#include <openvpn/server/servhalt.hpp>

namespace openvpn::SimpleMan {

/**
 * @brief Tunnel configuration pushed to every accepted client.
 *
 * @details
 * Deliberately flat and small: the subset of server directives needed for a
 * client to bring up a tunnel interface and keep the session alive. Anything
 * further goes in @c extra_push verbatim.
 */
struct Config : public RC<thread_unsafe_refcount>
{
    using Ptr = RCPtr<Config>;

    /** Tunnel-side address of the server, pushed as @c route-gateway. */
    IP::Addr gateway = IP::Addr::from_string("10.8.0.1");

    /** Prefix length of the tunnel subnet, pushed as an @c ifconfig netmask. */
    unsigned int prefix_len = 24;

    /** Seconds between keepalive pings pushed to the client. */
    unsigned int keepalive_ping = 10;

    /** Seconds of silence after which the client restarts the session. */
    unsigned int keepalive_timeout = 60;

    /** Extra push directives, appended verbatim (e.g. @c "route 10.0.0.0 255.0.0.0"). */
    std::vector<std::string> extra_push;
};

/**
 * @brief Per-client policy object: approves the client and builds its push reply.
 *
 * @details
 * The protocol session creates one of these on first needing a policy decision
 * and holds it as its @c ManLink::send.
 *
 * The push reply is emitted exactly once, when both preconditions are met: the
 * client has authenticated, and a push has been requested. Those arrive in
 * either order. A client advertising @c IV_PROTO request-push triggers
 * @c push_request() from @c ServerProto::Session::active(), which can precede
 * or follow @c auth_request(); an older client sends @c PUSH_REQUEST on the
 * control channel after authenticating. Gating on both flags rather than
 * pushing from whichever callback arrives handles every ordering without
 * double-pushing, and a duplicate push reply would reinitialize the client's
 * data channel mid-session.
 */
class ManSend : public ManClientInstance::Send
{
  public:
    using Ptr = RCPtr<ManSend>;

    /**
     * @brief Construct the per-client policy object.
     * @param parent Non-owning back-pointer to the protocol session. Used to
     *  deliver the push reply and any failure verdict. Must outlive this object,
     *  which the session guarantees by calling @c stop() during teardown.
     * @param config Shared tunnel configuration pushed to this client.
     * @param instance_id Process-unique identifier for logging.
     * @param lease This client's address, held for as long as this object
     *  lives; releasing it drops both the pool entry and the route.
     */
    ManSend(ManClientInstance::Recv *parent,
            Config::Ptr config,
            const std::uint64_t instance_id,
            PeerRoutes::Lease &&lease)
        : parent_(parent),
          config_(std::move(config)),
          instance_id_(instance_id),
          lease_(std::move(lease))
    {
        instance_name_ = "CLI_" + std::to_string(instance_id_);
    }

    /**
     * @brief Handle an authentication request from the protocol layer.
     * @details Approves unconditionally, records the client's identity for
     *  logging, and pushes if a push has already been requested.
     * @param auth_creds Credentials supplied by the client. Username is retained
     *  for logging; the password is not examined.
     * @param auth_cert Verified client certificate, or null if none was
     *  presented. Retained for logging only.
     * @param peer_addr Client's transport address.
     */
    void auth_request(const AuthCreds::Ptr &auth_creds,
                      const AuthCert::Ptr &auth_cert,
                      const PeerAddr::Ptr &peer_addr) override
    {
        if (auth_creds && !auth_creds->username.empty())
            username_ = auth_creds->username;
        else if (auth_cert)
            username_ = auth_cert->get_cn();

        OPENVPN_LOG(instance_name_ << " : auth accepted"
                                   << (username_.empty() ? "" : " user=" + username_)
                                   << (peer_addr ? " from " + peer_addr->to_string() : "")
                                   << " addr=" << lease_.addr().to_string());

        authenticated_ = true;
        maybe_push();
    }

    /**
     * @brief Handle a push request from the protocol layer.
     * @details Records the negotiated data-channel cipher and this session's
     *  local peer id so the push reply can echo them, then pushes if the
     *  client has already authenticated.
     * @param pconf Protocol configuration as negotiated for this session. Read
     *  for the selected data-channel cipher and local peer id; not retained.
     */
    void push_request(ProtoContext::ProtoConfig::Ptr pconf) override
    {
        if (pconf)
        {
            cipher_ = pconf->dc.cipher();
            local_peer_id_ = pconf->local_peer_id;
        }
        push_requested_ = true;
        maybe_push();
    }

    /**
     * @brief Override the keepalive parameters negotiated by the protocol layer.
     * @param keepalive_ping Ping interval in seconds, replaced with the
     *  configured value.
     * @param keepalive_timeout Restart timeout in seconds, replaced with the
     *  configured value.
     */
    void keepalive_override(unsigned int &keepalive_ping,
                            unsigned int &keepalive_timeout) override
    {
        keepalive_ping = config_->keepalive_ping;
        keepalive_timeout = config_->keepalive_timeout;
    }

    /**
     * @brief Notified that the session is about to stop.
     * @details Suppresses any further push attempt so a late callback during
     *  teardown cannot reach a dying session.
     */
    void pre_stop() override
    {
        stopped_ = true;
    }

    /**
     * @brief Release this client's pool address and the back-pointer to the
     *  owning session.
     * @details Idempotent; called during session teardown. Dropping the lease
     *  returns the address to the pool and removes its route in one step, so
     *  a session denied or aborted before a tun instance ever existed still
     *  gives its address back (see peerroutes.hpp).
     */
    void stop() override
    {
        stopped_ = true;
        lease_.release();
        parent_ = nullptr;
    }

    /**
     * @brief Report whether this object has been stopped.
     * @return True once @c pre_stop() or @c stop() has been called.
     */
    bool is_stopped() const override
    {
        return stopped_;
    }

    /**
     * @brief Human-readable name for this client instance, used in logs.
     * @return A process-unique name of the form @c CLI_<id>.
     */
    std::string instance_name() const override
    {
        return instance_name_;
    }

    /**
     * @brief Process-unique numeric identifier for this client instance.
     * @return The identifier assigned at construction.
     */
    std::uint64_t instance_id() const override
    {
        return instance_id_;
    }

    /**
     * @brief Report final or periodic bandwidth statistics for this client.
     * @param ps Byte and packet counters for the session.
     * @param is_final True if this is the last report before teardown.
     */
    void stats_notify(const PeerStats &ps, const bool is_final) override
    {
        if (is_final)
            OPENVPN_LOG(instance_name_ << " : final stats " << ps.to_string());
    }

    /**
     * @brief Handle a client transport-address change (peer float).
     * @param addr The client's new transport address.
     */
    void float_notify(const PeerAddr::Ptr &addr) override
    {
        if (addr)
            OPENVPN_LOG(instance_name_ << " : floated to " << addr->to_string());
    }

    /**
     * @brief Handle an application control-channel message from the client.
     * @param msg The message text.
     */
    void app_control(const std::string &msg) override
    {
        OPENVPN_LOG(instance_name_ << " : app control: " << msg);
    }

    /**
     * @brief Describe the connected user.
     * @param show_userprop Whether to include user properties. Unused; this
     *  implementation maintains none.
     * @return A short human-readable description of the session.
     */
    std::string describe_user([[maybe_unused]] const bool show_userprop) override
    {
        return instance_name_ + " " + username_ + " " + lease_.addr().to_string();
    }

    /**
     * @brief Disconnect this client.
     * @param type Halt or restart disposition sent to the client.
     * @param auth_status Authentication status code. Unused here.
     * @param reason Server-side reason, for logs.
     * @param client_reason Reason conveyed to the client.
     */
    void disconnect_user(const HaltRestart::Type type,
                         [[maybe_unused]] const AuthStatus::Type auth_status,
                         const std::string &reason,
                         const std::string &client_reason) override
    {
        OPENVPN_LOG(instance_name_ << " : disconnect: " << reason);
        if (parent_ && !stopped_)
            parent_->push_halt_restart_msg(type, reason, client_reason);
    }

    /**
     * @brief Dump internal state for debugging.
     * @return A description of this instance's current state.
     */
    std::string to_string_debug() const override
    {
        return instance_name_ + " " + username_ + " " + lease_.addr().to_string()
               + (authenticated_ ? " auth" : " noauth")
               + (pushed_ ? " pushed" : " nopush");
    }

    /**
     * @brief IP-mapped ACL notification. Not supported by this implementation.
     * @param ipma Kernel-supplied ACL mapping. Ignored.
     */
    void ipma_notify([[maybe_unused]] const struct ovpn_tun_head_ipma &ipma) override
    {
    }

    /**
     * @brief ACL index assignment. Not supported by this implementation.
     * @param acl_index Ignored ACL index.
     * @param username Ignored username.
     * @param challenge Ignored challenge flag.
     */
    void set_acl_index([[maybe_unused]] const int acl_index,
                       [[maybe_unused]] const std::string *username,
                       [[maybe_unused]] const bool challenge) override
    {
    }

    /**
     * @brief Local user-property update. Not supported by this implementation.
     */
    void userprop_local_update() override
    {
    }

    /**
     * @brief DOMA ACL manipulation. Not supported by this implementation.
     * @param root Ignored request document.
     * @return A null JSON value.
     */
    Json::Value doma_acl([[maybe_unused]] const Json::Value &root) override
    {
        return Json::Value();
    }

    /**
     * @brief Send an informational control message to the client.
     * @param info Message buffer. Discarded by this implementation.
     */
    void post_info_user([[maybe_unused]] BufferPtr &&info) override
    {
    }

  private:
    /**
     * @brief Emit the push reply once both preconditions are satisfied.
     * @details No-op unless the client has authenticated, a push has been
     *  requested, nothing has been pushed yet, and the session is live. See the
     *  class documentation for why both flags are required.
     */
    void maybe_push()
    {
        if (pushed_ || stopped_ || !authenticated_ || !push_requested_ || !parent_)
            return;
        pushed_ = true;

        std::vector<BufferPtr> msgs;
        msgs.push_back(build_push_reply());
        parent_->push_reply(std::move(msgs));
    }

    /**
     * @brief Build the @c PUSH_REPLY control message for this client.
     * @details Emits topology, gateway, the client's assigned address and
     *  netmask, keepalive timers, the negotiated data-channel cipher when one
     *  was selected, and any configured extra directives.
     * @return A buffer holding the comma-separated reply. Not null-terminated;
     *  @c ServerProto::Session::push_reply() terminates it before sending.
     */
    BufferPtr build_push_reply() const
    {
        std::ostringstream os;
        os << "PUSH_REPLY";
        os << ",topology subnet";
        os << ",route-gateway " << config_->gateway.to_string();
        os << ",ifconfig " << lease_.addr().to_string() << ' '
           << IP::Addr::netmask_from_prefix_len(config_->gateway.version(),
                                                config_->prefix_len)
                  .to_string();
        os << ",ping " << config_->keepalive_ping;
        os << ",ping-restart " << config_->keepalive_timeout;
        if (CryptoAlgs::defined(cipher_))
            os << ",cipher " << CryptoAlgs::name(cipher_);
        if (local_peer_id_ >= 0)
        {
            // Tells the client to stamp its own outgoing DATA_V2 packets with this id
            os << ",peer-id " << local_peer_id_;
        }
        for (const auto &d : config_->extra_push)
            os << ',' << d;

        const std::string reply = os.str();
        OPENVPN_LOG(instance_name_ << " : " << reply);

        BufferPtr buf = BufferAllocatedRc::Create(reply.size() + 1);
        buf_append_string(*buf, reply);
        return buf;
    }

    ManClientInstance::Recv *parent_;
    Config::Ptr config_;
    std::uint64_t instance_id_;
    PeerRoutes::Lease lease_;
    std::string instance_name_;
    std::string username_;
    CryptoAlgs::Type cipher_ = CryptoAlgs::NONE;
    int local_peer_id_ = -1;
    bool authenticated_ = false;
    bool push_requested_ = false;
    bool pushed_ = false;
    bool stopped_ = false;
};

/**
 * @brief ManFactory producing one @c ManSend per connected client.
 *
 * @details
 * Held by @c ServerProto::Factory as its @c man_factory. Owns the shared push
 * configuration; address assignment is delegated to @c PeerRoutes, which the
 * tun layer also shares, so the two layers agree on who owns what address
 * without either being handed the other's data directly (see
 * `peerroutes.hpp`).
 */
class ManFactory : public ManClientInstance::Factory
{
  public:
    using Ptr = RCPtr<ManFactory>;

    /**
     * @brief Construct the factory.
     * @param config Tunnel configuration pushed to every client. Must be non-null.
     * @param pool Shared address pool. Borrowed; must outlive every
     *  @c ManSend this factory creates.
     * @param routes Shared route table the tun layer reads. Borrowed; same
     *  requirement.
     */
    ManFactory(Config::Ptr config, PeerRoutes::AddressPool *pool, PeerRoutes::RouteTable *routes)
        : config_(std::move(config)),
          pool_(pool),
          routes_(routes)
    {
    }

    /**
     * @brief Start the management layer.
     * @details Nothing to start; state is created per client.
     */
    void start() override
    {
    }

    /**
     * @brief Stop the management layer.
     * @details Nothing to stop; per-client objects are torn down by their sessions.
     */
    void stop() override
    {
    }

    /**
     * @brief Create the policy object for one client session.
     * @param instance The protocol session requesting a policy layer. Borrowed,
     *  not owned. Also the session identity registered with @c PeerRoutes, via
     *  the sibling @c TunClientInstance::Recv interface the same @c Session
     *  implements (see `peerroutes.hpp`).
     * @return A new @c ManSend with the next assigned address.
     * @throws PeerRoutes::peer_routes_error if the address range is exhausted.
     */
    ManClientInstance::Send::Ptr new_man_obj(ManClientInstance::Recv *instance) override
    {
        PeerRoutes::Lease lease(*pool_, *routes_, dynamic_cast<TunClientInstance::Recv *>(instance));
        return ManClientInstance::Send::Ptr(
            new ManSend(instance, config_, ++last_instance_id_, std::move(lease)));
    }

  private:
    Config::Ptr config_;
    PeerRoutes::AddressPool *pool_;
    PeerRoutes::RouteTable *routes_;
    std::uint64_t last_instance_id_ = 0;
};

} // namespace openvpn::SimpleMan

#endif
