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
 * @brief The `ManClientInstance` adapter that drives an embedder's
 *  `ServerEventHandler` instead of hardcoding policy.
 *
 * @details
 * Plays the same role `simpleman.hpp` does for the bare reference server:
 * held by `ServerProto::Factory` as its `man_factory`, one `ManSend` per
 * connected client. Where `SimpleMan` always approves and pushes a fixed
 * config, `HandlerMan::ManSend` calls out to the embedder's handler for the
 * auth verdict and otherwise follows the same push-gating shape `SimpleMan`
 * already established (see that file's doc comment for why both orderings
 * of auth-then-push and push-then-auth must be handled without double
 * pushing).
 *
 * This file also defines `AuthDecision`'s member functions
 * (`server_api.hpp`), which is the whole reason `ManSend` additionally
 * implements `detail::AuthTarget`: that small internal interface is
 * what lets `AuthDecision` stay a concrete, non-template type in the public
 * header while still completing against a `Handler`-specific object here.
 * It is never exposed to the embedder -- the same "legacy glue confined to
 * the boundary" idiom the RFC already uses for `ManClientInstance` itself
 * (RFC §5.5).
 *
 * Per RFC §5.8, this file's `ManSend`/`ManFactory` are legacy-idiom
 * (`ManClientInstance` is `RC<>`-based; there is no other way to implement
 * it), same boundary already established for `simpleman.hpp` and
 * `tunsink.hpp`. `Handler` itself is never touched by any of that: it is
 * called through the `ServerEventHandler` concept only, with static dispatch.
 */

#ifndef OPENVPN_SERVER_API_HANDLER_MAN_H
#define OPENVPN_SERVER_API_HANDLER_MAN_H

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
#include <openvpn/server/dcoserv.hpp>
#include <openvpn/server/manage.hpp>
#include <openvpn/server/peeraddr.hpp>
#include <openvpn/server/peerroutes.hpp>
#include <openvpn/server/peerstats.hpp>
#include <openvpn/server/servhalt.hpp>
#include <openvpn/server_api/server_api.hpp>
#include <openvpn/transport/server/transbase.hpp>

namespace openvpn::ServerAPI::detail {

/**
 * @brief Internal completion target for `AuthDecision`. Never exposed to the
 *  embedder; `ManSend<Handler>` (below) is the only implementation.
 */
class AuthTarget : public virtual RC<thread_unsafe_refcount>
{
  public:
    using Ptr = RCPtr<AuthTarget>;

    virtual void complete_allow() = 0;
    virtual void complete_deny(DenyReason reason) = 0;
    virtual void complete_pending(unsigned int timeout_seconds) = 0;

    AuthTarget() = default;
    AuthTarget(const AuthTarget &) = delete;
    AuthTarget &operator=(const AuthTarget &) = delete;
    AuthTarget(AuthTarget &&) = delete;
    AuthTarget &operator=(AuthTarget &&) = delete;
    ~AuthTarget() override = default;
};

} // namespace openvpn::ServerAPI::detail

namespace openvpn::ServerAPI {

inline AuthDecision::AuthDecision(RCPtr<detail::AuthTarget> target)
    : target_(std::move(target))
{
}

inline AuthDecision::AuthDecision(AuthDecision &&) noexcept = default;
inline AuthDecision &AuthDecision::operator=(AuthDecision &&) noexcept = default;
inline AuthDecision::~AuthDecision() = default;

inline void AuthDecision::allow()
{
    if (target_)
        target_->complete_allow();
}

inline void AuthDecision::deny(const DenyReason reason)
{
    if (target_)
        target_->complete_deny(reason);
}

inline void AuthDecision::pending(const unsigned int timeout_seconds)
{
    if (target_)
        target_->complete_pending(timeout_seconds);
}

namespace HandlerMan {

/**
 * @brief Tunnel configuration pushed to every accepted client.
 * @details Same shape as `SimpleMan::Config`; not shared with it to avoid
 *  coupling the two ahead of it being clear whether `SimpleMan` stays a
 *  standalone option once `ServerAPI` exists.
 */
struct Config : public RC<thread_unsafe_refcount>
{
    using Ptr = RCPtr<Config>;

    IP::Addr gateway = IP::Addr::from_string("10.8.0.1");
    unsigned int prefix_len = 24;
    unsigned int keepalive_ping = 10;
    unsigned int keepalive_timeout = 60;
    std::vector<std::string> extra_push;
};

/**
 * @brief Per-client policy object driving an embedder's `Handler` for the
 *  auth verdict.
 */
template <ServerEventHandler Handler>
class ManSend : public ManClientInstance::Send, public detail::AuthTarget
{
  public:
    using Ptr = RCPtr<ManSend>;

    ManSend(ManClientInstance::Recv *parent,
            TransportClientInstance::Recv *transport_recv,
            Config::Ptr config,
            Handler &handler,
            DcoServ::Channel::Ptr dco_channel,
            const std::uint64_t instance_id,
            PeerRoutes::Lease &&lease)
        : parent_(parent),
          transport_recv_(transport_recv),
          config_(std::move(config)),
          handler_(handler),
          dco_channel_(std::move(dco_channel)),
          instance_id_(instance_id),
          lease_(std::move(lease))
    {
        instance_name_ = "CLI_" + std::to_string(instance_id_);
    }

    // -- ManClientInstance::Send --

    void auth_request(const AuthCreds::Ptr &auth_creds,
                      const AuthCert::Ptr &auth_cert,
                      const PeerAddr::Ptr &peer_addr) override
    {
        if (auth_creds && !auth_creds->username.empty())
            username_ = auth_creds->username;
        if (auth_cert)
            cert_common_name_ = auth_cert->get_cn();
        peer_addr_ = peer_addr;

        AuthRequest req;
        req.common_name = cert_common_name_;
        req.username = username_;
        if (peer_addr)
            req.transport_info = peer_addr->to_string();
        handler_.on_client_auth(req, AuthDecision(detail::AuthTarget::Ptr(this)));
    }

    void push_request(ProtoContext::ProtoConfig::Ptr pconf) override
    {
        if (pconf)
        {
            cipher_ = pconf->dc.cipher();
            local_peer_id_ = pconf->local_peer_id;
            pconf_ = std::move(pconf);
        }
        push_requested_ = true;
        maybe_engage_dco();
        maybe_push();
    }

    void keepalive_override(unsigned int &keepalive_ping,
                            unsigned int &keepalive_timeout) override
    {
        keepalive_ping = config_->keepalive_ping;
        keepalive_timeout = config_->keepalive_timeout;
    }

    void disconnect_notify(const DisconnectCause cause) override
    {
        disconnect_cause_ = cause;
    }

    void pre_stop() override
    {
        stopped_ = true;
    }

    void stop() override
    {
        stopped_ = true;
        // Proactive teardown: keys are already gone by this point
        if (dco_channel_ && dco_engaged_)
            dco_channel_->del_peer(local_peer_id_);

        notify_disconnected(reason_for(disconnect_cause_));

        // Drops the route and returns the address to the pool
        lease_.release();

        parent_ = nullptr;
    }

    bool is_stopped() const override
    {
        return stopped_;
    }

    std::string instance_name() const override
    {
        return instance_name_;
    }

    std::uint64_t instance_id() const override
    {
        return instance_id_;
    }

    void stats_notify(const PeerStats &ps, const bool is_final) override
    {
        if (is_final)
            OPENVPN_LOG(instance_name_ << " : final stats " << ps.to_string());
    }

    void float_notify(const PeerAddr::Ptr &addr) override
    {
        if (addr)
            OPENVPN_LOG(instance_name_ << " : floated to " << addr->to_string());
    }

    void app_control(const std::string &msg) override
    {
        OPENVPN_LOG(instance_name_ << " : app control: " << msg);
    }

    std::string describe_user(const bool /* show_userprop */) override
    {
        return instance_name_ + " " + username_ + " " + lease_.addr().to_string();
    }

    void disconnect_user(const HaltRestart::Type type,
                         const AuthStatus::Type /* auth_status */,
                         const std::string &reason,
                         const std::string &client_reason) override
    {
        OPENVPN_LOG(instance_name_ << " : disconnect: " << reason);

        if (parent_ && !stopped_)
            parent_->push_halt_restart_msg(type, reason, client_reason);
    }

    std::string to_string_debug() const override
    {
        return instance_name_ + " " + username_ + " " + lease_.addr().to_string()
               + (verdict_ == Verdict::Allowed ? " allowed" : " noauth")
               + (pushed_ ? " pushed" : " nopush");
    }

    void ipma_notify(const struct ovpn_tun_head_ipma & /* ipma */) override
    {
    }

    void set_acl_index(const int /* acl_index */,
                       const std::string * /* username */,
                       const bool /* challenge */) override
    {
    }

    void userprop_local_update() override
    {
    }

    Json::Value doma_acl(const Json::Value & /* root */) override
    {
        return Json::Value();
    }

    void post_info_user(BufferPtr && /* info */) override
    {
    }

    // -- detail::AuthTarget --

    void complete_allow() override
    {
        if (stopped_ || verdict_ != Verdict::Pending)
            return;
        verdict_ = Verdict::Allowed;
        const ClientInfo info = client_info();
        connected_notified_ = true;
        handler_.on_client_connected(info);
        maybe_engage_dco();
        maybe_push();
    }

    void complete_deny(const DenyReason reason) override
    {
        if (stopped_ || verdict_ != Verdict::Pending)
            return;
        verdict_ = Verdict::Denied;

        disconnect_notified_ = true;
        handler_.on_client_disconnected(client_info(), DisconnectReason::AuthFailed);

        if (parent_)
            parent_->auth_failed(deny_reason_str(reason), deny_reason_str(reason));
    }

    void complete_pending(const unsigned int timeout_seconds) override
    {
        if (stopped_ || verdict_ != Verdict::Pending)
            return;
        if (parent_)
            parent_->schedule_auth_pending_timeout(timeout_seconds);
    }

  private:
    enum class Verdict
    {
        Pending,
        Allowed,
        Denied,
    };

    static const char *deny_reason_str(const DenyReason reason)
    {
        switch (reason)
        {
        case DenyReason::InvalidCredentials:
            return "invalid credentials";
        case DenyReason::PolicyDenied:
            return "denied by policy";
        case DenyReason::ServerFull:
            return "server full";
        }
        return "denied";
    }

    /**
     * @brief Build the @c ClientInfo snapshot passed to
     *  `on_client_connected`/`on_client_disconnected`.
     * @return A populated @c ClientInfo for this session.
     */
    ClientInfo client_info() const
    {
        ClientInfo info;
        // Prefer the cert CN captured in auth_request()
        info.common_name = cert_common_name_.empty() ? username_ : cert_common_name_;
        info.username = username_;
        info.vpn_address = lease_.addr();
        info.session_id = instance_id_;
        if (peer_addr_)
            info.transport_info = peer_addr_->to_string();
        return info;
    }

    /**
     * @brief Map a protocol-layer teardown cause to the embedder-facing reason.
     * @param cause The cause recorded by the protocol session.
     * @return The corresponding @c DisconnectReason.
     */
    static DisconnectReason reason_for(const DisconnectCause cause)
    {
        using enum DisconnectCause;

        switch (cause)
        {
        case KEEPALIVE_TIMEOUT:
            return DisconnectReason::Timeout;
        case CLIENT_EXIT:
            return DisconnectReason::ClientRequested;
        case SERVER_SHUTDOWN:
            return DisconnectReason::ServerShutdown;
        case UNKNOWN:
        default:
            return DisconnectReason::SessionError;
        }
    }

    /**
     * @brief Report the session's end to the embedder, exactly once.
     * @details Only for a client that reached @c on_client_connected. A denied
     *  one is reported by @c complete_deny() instead, which is the only other
     *  path that may call @c on_client_disconnected.
     * @param reason Why the session ended.
     */
    void notify_disconnected(const DisconnectReason reason)
    {
        if (!connected_notified_ || disconnect_notified_)
            return;
        disconnect_notified_ = true;
        handler_.on_client_disconnected(client_info(), reason);
    }

    /**
     * @brief Engage kernel DCO for this session once both preconditions are
     *  satisfied.
     * @details Mirrors `maybe_push()`'s dual-call-site shape exactly (called
     *  from both `push_request()` and `complete_allow()`, since either can
     *  arrive first): a session is only registered as a kernel peer once it
     *  is both admitted (`verdict_ == Allowed` -- a denied client must never
     *  get real kernel keys installed for it) and has pushed
     *  (`pconf_` available, which is where `local_peer_id_` and the crypto
     *  factory to wrap come from). One-shot, guarded by `dco_engaged_`.
     */
    void maybe_engage_dco()
    {
        if (dco_engaged_ || !dco_channel_ || !transport_recv_)
            return;
        if (verdict_ != Verdict::Allowed || !pconf_ || local_peer_id_ < 0)
            return;
        dco_engaged_ = true;

        AddrPort remote;
        if (peer_addr_)
            remote = peer_addr_->remote;

        DcoServ::PeerReceiver::Ptr receiver = dco_channel_->add_peer(
            local_peer_id_,
            lease_.addr(),
            remote,
            transport_recv_,
            config_->keepalive_ping,
            config_->keepalive_timeout);

        transport_recv_->override_dc_factory(
            CryptoDCFactory::Ptr(new KoRekey::Factory(pconf_->dc.factory(), receiver, pconf_->frame)));

        // Kernel now owns keepalive
        unsigned int ka_ping = 0, ka_timeout = 0;
        transport_recv_->disable_keepalive(ka_ping, ka_timeout);
    }

    /**
     * @brief Emit the push reply once both preconditions are satisfied.
     * @details Mirrors `SimpleMan::ManSend::maybe_push()` exactly, with the
     *  auth flag now handler-driven (`complete_allow()`) instead of
     *  unconditional.
     */
    void maybe_push()
    {
        if (pushed_ || stopped_ || verdict_ != Verdict::Allowed || !push_requested_ || !parent_)
            return;
        pushed_ = true;

        std::vector<BufferPtr> msgs;
        msgs.push_back(build_push_reply());
        parent_->push_reply(std::move(msgs));
    }

    /**
     * @brief Build the `PUSH_REPLY` control message for this client.
     * @details Duplicates `SimpleMan::ManSend::build_push_reply()`'s string
     *  construction deliberately rather than sharing it: the two call sites
     *  are still settling independently (this one drives an embedder's
     *  handler, that one is a fixed policy), and factoring them together now
     *  would be speculative. Worth revisiting once `ServerAPI`'s shape is
     *  no longer moving.
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
            os << ",peer-id " << local_peer_id_;
        for (const auto &d : config_->extra_push)
            os << ',' << d;

        const std::string reply = os.str();
        OPENVPN_LOG(instance_name_ << " : " << reply);

        BufferPtr buf = BufferAllocatedRc::Create(reply.size() + 1);
        buf_append_string(*buf, reply);
        return buf;
    }

    ManClientInstance::Recv *parent_;
    TransportClientInstance::Recv *transport_recv_;
    Config::Ptr config_;
    Handler &handler_;
    DcoServ::Channel::Ptr dco_channel_;
    std::uint64_t instance_id_;
    PeerRoutes::Lease lease_;
    std::string instance_name_;
    std::string username_;
    std::string cert_common_name_;
    PeerAddr::Ptr peer_addr_;
    ProtoContext::ProtoConfig::Ptr pconf_;
    CryptoAlgs::Type cipher_ = CryptoAlgs::NONE;
    int local_peer_id_ = -1;
    Verdict verdict_ = Verdict::Pending;
    bool push_requested_ = false;
    bool pushed_ = false;
    bool stopped_ = false;
    bool connected_notified_ = false;
    bool disconnect_notified_ = false;
    bool dco_engaged_ = false;
    DisconnectCause disconnect_cause_ = DisconnectCause::UNKNOWN;
};

/**
 * @brief ManFactory producing one `ManSend<Handler>` per connected client.
 */
template <ServerEventHandler Handler>
class ManFactory : public ManClientInstance::Factory
{
  public:
    using Ptr = RCPtr<ManFactory>;

    ManFactory(Config::Ptr config,
               Handler &handler,
               PeerRoutes::AddressPool *pool,
               PeerRoutes::RouteTable *routes,
               DcoServ::Channel::Ptr dco_channel = DcoServ::Channel::Ptr())
        : config_(std::move(config)),
          handler_(handler),
          pool_(pool),
          routes_(routes),
          dco_channel_(std::move(dco_channel))
    {
    }

    void start() override
    {
    }

    void stop() override
    {
    }

    ManClientInstance::Send::Ptr new_man_obj(ManClientInstance::Recv *instance) override
    {
        PeerRoutes::Lease lease(*pool_, *routes_, dynamic_cast<TunClientInstance::Recv *>(instance));
        auto *transport_recv = dynamic_cast<TransportClientInstance::Recv *>(instance);
        return ManClientInstance::Send::Ptr(
            new ManSend<Handler>(instance, transport_recv, config_, handler_, dco_channel_, ++last_instance_id_, std::move(lease)));
    }

  private:
    Config::Ptr config_;
    Handler &handler_;
    PeerRoutes::AddressPool *pool_;
    PeerRoutes::RouteTable *routes_;
    DcoServ::Channel::Ptr dco_channel_;
    std::uint64_t last_instance_id_ = 0;
};

} // namespace HandlerMan
} // namespace openvpn::ServerAPI

#endif
