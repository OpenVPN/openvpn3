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
 * @brief Public embedding surface for the O3 server (RFC `rfc-o3-server-engine.md`
 *  §5.5): the types an embedder's `ServerEventHandler` exchanges with the
 *  server. `openvpn_server.hpp` is the class that actually runs one.
 *
 * @details
 * Mirrors how `client/ovpncli.hpp` (`ClientAPI`) is consumed, with one
 * deliberate difference: `ClientAPI` predates the RFC §5.8 code standard and
 * uses virtual base classes (`TunBuilderBase`, `LogReceiver`) as its
 * extension points. This surface does not -- the embedder's handler is a
 * concept-constrained type parameter (`ServerEventHandler` below), not
 * something that inherits from anything here. `AuthDecision`'s member
 * functions are defined in `handler_man.hpp`, once the type it completes
 * against is known; this header only needs to declare its shape.
 *
 * Every field here existed already, scattered across
 * `PeerRoutes::Config`/`TunReal::Config`/`SimpleMan::Config`/
 * `UDPTransportServer::Config` and the reference binary's own `ServerArgs`.
 * PKI fields are PEM *content*, not file paths, matching `ClientAPI::Config`'s
 * own `content` convention: an embedder with certificates in a keystore
 * rather than a filesystem should not need one. `test/ovpnserv/serv.cpp`
 * reads files into strings before populating this struct, the same way
 * `test/ovpncli/cli.cpp` reads a profile before calling `eval_config()`.
 */

#ifndef OPENVPN_SERVER_API_SERVER_API_H
#define OPENVPN_SERVER_API_SERVER_API_H

#include <cstdint>
#include <string>
#include <vector>

#include <openvpn/addr/ip.hpp>
#include <openvpn/common/rc.hpp>

namespace openvpn::ServerAPI {

/**
 * @brief Server configuration: listener, PKI, pool, routes, perf tuning.
 * @details Sketch, not a contract -- shape settles alongside the rest of
 *  `ServerAPI` (RFC §5.5).
 */
struct Config
{
    // Listener
    std::string bind_addr = "0.0.0.0";
    unsigned short port = 1194;

    std::string ca;
    std::string cert;
    std::string key;
    std::string dh;
    std::string crl; // CRL bundle; matches ".ovpn"'s crl-verify
    std::string tls_auth;
    int tls_auth_key_direction = 0;
    std::string tls_crypt;
    std::string tls_crypt_v2;

    bool client_cert_optional = false;

    // Data channel
    std::string cipher = "AES-256-GCM";
    unsigned int renegotiate_seconds = 3600;

    // Pool / routes. gateway is the server's own tunnel-side address;
    // pool_start/pool_size is the range handed out to clients.
    IP::Addr gateway = IP::Addr::from_string("10.8.0.1");
    IP::Addr pool_start = IP::Addr::from_string("10.8.0.2");
    unsigned int pool_size = 252;
    unsigned int prefix_len = 24;
    std::vector<std::string> extra_push;

    // Keepalive
    unsigned int keepalive_ping = 10;
    unsigned int keepalive_timeout = 60;

    // Data plane
    std::string tun_name; // empty lets the kernel assign one
    unsigned int tun_mtu = 1500;
    bool null_tun = false;         // control-plane-only diagnostic mode, see tunsink.hpp
    bool client_to_client = false; // off by default, enforced by netpolicy.hpp

    bool disable_dco = false;

    // Perf / limits
    int rcvbuf = 0;
    int sndbuf = 0;
    std::size_t max_clients = 1024;
    int n_parallel = 4;
    unsigned int reap_interval_seconds = 5;
};

/**
 * @brief What a connecting client presented, handed to
 *  `ServerEventHandler::on_client_auth`.
 * @details Deliberately omits any password/credential secret: this is a
 *  record for the embedder to make a decision from, not a place to retain
 *  one longer than the decision takes.
 */
struct AuthRequest
{
    /** Client certificate common name, if a client certificate was presented. */
    std::string common_name;

    /** Username from auth-user-pass, if presented. */
    std::string username;

    /** Client's transport address, e.g. "UDP 203.0.113.7:54321". */
    std::string transport_info;
};

/**
 * @brief A connected client, handed to `on_client_connected`/`on_client_disconnected`.
 */
struct ClientInfo
{
    std::string common_name;
    std::string username;
    IP::Addr vpn_address;
    std::string transport_info;
    std::uint64_t session_id = 0;
};

/**
 * @brief Why a client disconnected, handed to `on_client_disconnected`.
 */
enum class DisconnectReason
{
    AuthFailed,
    Timeout,
    ServerShutdown,
    ClientRequested,

    /**
     * Teardown with no more specific cause: a transport error, a protocol
     * error, or session invalidation other than a keepalive timeout. Those
     * paths carry no signal that distinguishes them, so they are reported as
     * one reason rather than guessed at.
     */
    SessionError,
};

/**
 * @brief Render a disconnect reason for logging.
 * @param reason The reason to render.
 * @return A stable, human-readable name.
 */
inline std::string to_string(const DisconnectReason reason)
{
    using enum DisconnectReason;

    switch (reason)
    {
    case AuthFailed:
        return "AuthFailed";
    case Timeout:
        return "Timeout";
    case ServerShutdown:
        return "ServerShutdown";
    case ClientRequested:
        return "ClientRequested";
    case SessionError:
        return "SessionError";
    default:
        return "DisconnectReason_?";
    }
}

/**
 * @brief Aggregate server counters, handed to `on_stats`.
 */
struct ServerStats
{
    std::size_t connected_clients = 0;
    std::uint64_t total_rx_bytes = 0;
    std::uint64_t total_tx_bytes = 0;
};

/**
 * @brief Why an auth request was denied, given to `AuthDecision::deny`.
 */
enum class DenyReason
{
    InvalidCredentials,
    PolicyDenied,
    ServerFull,
};

namespace detail {

class AuthTarget;
} // namespace detail

/**
 * @brief Completion handle for one client's auth verdict.
 *
 * @details
 * Movable, not copyable, and not thread-safe. May be completed inline (during
 * `on_client_auth`) or retained and completed later, but only ever from the
 * server's control thread -- the thread that invoked `on_client_auth`. The
 * verdict is applied inline into single-threaded protocol state, and the
 * handle holds a non-atomic reference to that state, so destroying an
 * `AuthDecision` belongs on that thread as much as completing one does.
 *
 * An embedder whose decision is genuinely asynchronous (an SSO or database
 * lookup) marshals the completion back itself: call `pending()` to extend the
 * client's deadline, then complete from a callback that runs on the control
 * thread.
 *
 * Marshalling the verdict internally, so completion really would be safe from
 * any thread, wants the `io_context` to outlive the handle and the handle's
 * own reference to be released on the control thread. That is the shape to
 * reach for when this stops being a PoC; it is a larger ownership change than
 * the PoC needs.
 *
 * Completing an already-completed or already-disconnected instance is a
 * silent no-op, not an error -- an embedder's async decision racing a client
 * that gave up and disconnected is an expected outcome, not a bug to
 * report.
 *
 * A thin wrapper over what the control plane already does:
 * `servproto`'s `server_auth()` is fire-and-forget, and the verdict already
 * returns later via `ManClientInstance::Recv` (`push_reply()`/`auth_failed()`),
 * with `AUTH_PENDING` timeouts already first-class there. Method bodies live
 * in `handler_man.hpp`, where the type this completes against is defined.
 */
class AuthDecision
{
  public:
    AuthDecision(const AuthDecision &) = delete;
    AuthDecision &operator=(const AuthDecision &) = delete;
    AuthDecision(AuthDecision &&) noexcept;
    AuthDecision &operator=(AuthDecision &&) noexcept;
    ~AuthDecision();

    /** @brief Approve the client and let the connection proceed to push. */
    void allow();

    /** @brief Deny the client. */
    void deny(DenyReason reason);

    /**
     * @brief Defer the verdict (e.g. SSO/OTP in progress).
     * @param timeout_seconds How long the client waits before the server
     *  gives up and disconnects it.
     */
    void pending(unsigned int timeout_seconds);

    // Constructed only by handler_man.hpp, which owns the type this
    // completes against.
    explicit AuthDecision(RCPtr<detail::AuthTarget> target);

  private:
    RCPtr<detail::AuthTarget> target_;
};

/**
 * @brief Any type satisfying this can drive a server (RFC §5.5).
 * @details One compound concept, not one per callback: these are facets of a
 *  single server's lifecycle, not independently-owned subsystems. An embedder
 *  who wants to split auth/connect/stats across separate objects composes
 *  that on their own side into one type satisfying this concept.
 */
template <typename T>
concept ServerEventHandler = requires(T t,
                                      const AuthRequest &auth_req,
                                      AuthDecision auth_decision,
                                      const ClientInfo &client,
                                      DisconnectReason reason,
                                      const ServerStats &stats) {
    t.on_client_auth(auth_req, std::move(auth_decision));
    t.on_client_connected(client);
    t.on_client_disconnected(client, reason);
    t.on_stats(stats);
};

} // namespace openvpn::ServerAPI

#endif
