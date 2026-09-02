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
 * @brief `ServerAPI::OpenVPNServer` (RFC `rfc-o3-server-engine.md` §5.5): the
 *  class an embedder actually instantiates.
 *
 * @details
 * Wraps the wiring that used to live by hand in `test/ovpnserv/serv.cpp`'s
 * `main()` -- `PeerRoutes`' address pool and route table, a `HandlerMan::ManFactory`
 * in place of `SimpleMan`'s fixed accept-everyone policy, `TunReal`/`TunSink`,
 * `ServerProto::Factory`, `UDPTransportServer::Server`, and (whichever
 * data-plane backend is active) a `NetPolicy::Policy` attachment for IP
 * forwarding and client-to-client isolation -- behind one constructor and a
 * one-shot `start()`, with teardown owned by the destructor. `serv.cpp` becomes a thin
 * consumer defining a concrete `Handler`, the same relationship
 * `test/ovpncli/cli.cpp` has to `ClientAPI::OpenVPNClient`.
 *
 * Deliberately un-alike `OpenVPNClient::connect()`, which blocks the calling
 * thread until disconnect: `start()` builds everything synchronously (so a
 * configuration error -- bad PEM content, a port already in use -- throws on
 * the caller's thread, not silently on a background one) and then hands the
 * control `io_context` to a worker thread it owns, returning once that
 * thread is running. This matches RFC §5.5's sketch ("spawns control
 * io_context + engine workers") rather than the client's model.
 */

#ifndef OPENVPN_SERVER_API_OPENVPN_SERVER_H
#define OPENVPN_SERVER_API_OPENVPN_SERVER_H

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>
#include <openvpn/crypto/cryptodcsel.hpp>
#include <openvpn/crypto/tls_crypt_v2.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/init/initprocess.hpp>
#include <openvpn/io/io.hpp>
#include <openvpn/log/logger.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/random/mtrandapi.hpp>
#include <openvpn/server/dcoserv.hpp>
#include <openvpn/server/netpolicy.hpp>
#include <openvpn/server/tunsink.hpp>
#include <openvpn/server/peerroutes.hpp>
#include <openvpn/server/tunreal.hpp>
#include <openvpn/server/servproto.hpp>
#include <openvpn/server/tcptransserv.hpp>
#include <openvpn/server/udptransserv.hpp>
#include <openvpn/server_api/handler_man.hpp>
#include <openvpn/ssl/proto.hpp>
#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/ssl/sslconsts.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/transport/protocol.hpp>

namespace openvpn::ServerAPI {

/**
 * @brief A running (or not-yet-started) O3 server, parameterized on the
 *  embedder's event handler.
 * @tparam Handler A type satisfying @c ServerEventHandler.
 */
template <ServerEventHandler Handler>
class OpenVPNServer
{
  public:
    /**
     * @brief Construct the server. Does not start it.
     * @param config Server configuration; copied in.
     * @param handler The embedder's event handler. Borrowed, not owned --
     *  must outlive this object.
     */
    OpenVPNServer(Config config, Handler &handler)
        : config_(std::move(config)),
          handler_(handler)
    {
    }

    /** @brief Stops the server if still running, then joins its thread. */
    ~OpenVPNServer()
    {
        stop();
    }

    OpenVPNServer(const OpenVPNServer &) = delete;
    OpenVPNServer &operator=(const OpenVPNServer &) = delete;
    OpenVPNServer(OpenVPNServer &&) = delete;
    OpenVPNServer &operator=(OpenVPNServer &&) = delete;

    /**
     * @brief Build the server and start it running on an internal thread.
     * @details Opens the listener socket and (unless @c Config::null_tun) the
     *  tun device before returning, so a bind/permission failure surfaces
     *  here rather than silently inside the worker thread. On failure, every
     *  side effect already made (netfilter rules, sysctl toggles, netdevs) is
     *  rolled back before the exception propagates, so a caught failure
     *  leaves the host as it was.
     * @throws openvpn::Exception on configuration or setup failure.
     */
    void start()
    {
        // One-shot by design: a server runs once and is stopped by its own
        // destructor. Restart is constructing another one, which is why there
        // is no state to release here and no previous worker to re-join.
        if (started_)
            throw Exception("OpenVPNServer::start() may only be called once");
        started_ = true;

        try
        {
            build_and_start();
        }
        catch (...)
        {
            unwind_failed_start();
            throw;
        }
    }

  private:
    /**
     * @brief Stop the server and join its worker thread.
     * @details Private: a server is stopped by its own destructor and by
     *  nothing else. That is the whole thread-safety argument -- there is no
     *  contract to document about which thread may call this, because the only
     *  caller is destruction, which the owner already has to serialize against
     *  everything else.
     *
     *  Idempotent, and the join is skipped when the caller *is* the worker
     *  (joining yourself is @c resource_deadlock_would_occur, thrown out of an
     *  asio handler), which is reachable if a handler callback destroys the
     *  server.
     */
    void stop()
    {
        if (running_.exchange(false))
        {
            openvpn_io::post(*io_context_,
                             [this]()
                             {
                                 transport_->stop();
                                 net_policy_.shutdown();
                                 if (real_tun_device_)
                                     real_tun_device_->stop();
                                 if (dco_channel_)
                                     dco_channel_->stop();
                             });
        }

        if (thread_.joinable() && thread_.get_id() != std::this_thread::get_id())
            thread_.join();
    }

    /** @brief The body of @c start(), separated so a failure can unwind. */
    void build_and_start()
    {
        // The data plane and the address pool are IPv4-only. Checked here.
        if (config_.gateway.version() != IP::Addr::V4)
            throw Exception("IPv4-only data path: gateway must be an IPv4 address, got "
                            + config_.gateway.to_string());
        if (config_.pool_start.version() != IP::Addr::V4)
            throw Exception("IPv4-only data path: pool_start must be an IPv4 address, got "
                            + config_.pool_start.to_string());

        check_pool_within_subnet();

        io_context_ = std::make_unique<openvpn_io::io_context>(1);
        frame_ = frame_init_simple(2048);
        stats_.reset(new SessionStats());

        const auto proto_config = build_proto_config();

        PeerRoutes::Config peer_routes_config;
        peer_routes_config.pool_start = config_.pool_start;
        peer_routes_config.pool_size = config_.pool_size;
        address_pool_ = std::make_unique<PeerRoutes::AddressPool>(peer_routes_config);
        routes_ = std::make_unique<PeerRoutes::RouteTable>();

        HandlerMan::Config::Ptr man_config(new HandlerMan::Config());
        man_config->gateway = config_.gateway;
        man_config->prefix_len = config_.prefix_len;
        man_config->keepalive_ping = config_.keepalive_ping;
        man_config->keepalive_timeout = config_.keepalive_timeout;
        man_config->extra_push = config_.extra_push;
        // Canonical wire spelling, so the comparison against the peer's
        // announced list is exact regardless of how the operator spelled it.
        man_config->cipher = CryptoAlgs::name(CryptoAlgs::lookup(config_.cipher), "");

        // Announced only when DCO would otherwise have engaged, so a host
        // without DCO support does not get a misleading warning.
        if (config_.proto.is_tcp() && !config_.null_tun && !config_.disable_dco
            && CryptoAlgs::mode(CryptoAlgs::lookup(config_.cipher)) == CryptoAlgs::AEAD
            && DcoServ::Channel::available())
            OPENVPN_LOG("kernel DCO is available but will not be used with TCP");

        // Opportunistic DCO, matching OpenVPN 2.
        if (!config_.null_tun && !config_.disable_dco && !config_.proto.is_tcp()
            && CryptoAlgs::mode(CryptoAlgs::lookup(config_.cipher)) == CryptoAlgs::AEAD
            && DcoServ::Channel::available())
        {
            try
            {
                DcoServ::Config dco_config;
                dco_config.dev_name = config_.tun_name;
                dco_config.gateway = config_.gateway;
                dco_config.prefix_len = config_.prefix_len;
                dco_config.mtu = config_.tun_mtu;
                dco_channel_.reset(new DcoServ::Channel(*io_context_, dco_config));
            }
            catch (const std::exception &e)
            {
                OPENVPN_LOG("DCO unavailable, falling back to the classic data path: " << e.what());
                dco_channel_.reset();
            }
        }

        if (!dco_channel_ && !config_.null_tun)
        {
            TunReal::Config tun_config;
            tun_config.dev_name = config_.tun_name;
            tun_config.gateway = config_.gateway;
            tun_config.prefix_len = config_.prefix_len;
            tun_config.mtu = config_.tun_mtu;
            real_tun_device_.reset(new TunReal::Device(*io_context_, tun_config, frame_, stats_, routes_.get()));
        }

        if (dco_channel_ || real_tun_device_)
        {
            NetPolicy::Attachment net_att;
            net_att.dev_name = dco_channel_ ? dco_channel_->iface_name() : real_tun_device_->iface_name();
            net_att.gateway = config_.gateway;
            net_att.prefix_len = config_.prefix_len;
            net_att.client_to_client = config_.client_to_client;
            net_policy_.attach(net_att);
        }

        ServerProto::Factory::Ptr proto_factory(new ServerProto::Factory(*io_context_, *proto_config));
        proto_factory->proto_context_config = proto_config;
        proto_factory->stats = stats_;
        proto_factory->man_factory.reset(new HandlerMan::ManFactory<Handler>(man_config, handler_, address_pool_.get(), routes_.get(), dco_channel_));
        if (dco_channel_)
            proto_factory->tun_factory.reset(new TunSink::TunFactory());
        else if (real_tun_device_)
            proto_factory->tun_factory.reset(new TunReal::TunFactory(real_tun_device_));
        else
            proto_factory->tun_factory.reset(new TunSink::TunFactory());

        if (config_.proto.is_tcp())
        {
            TCPTransportServer::Config::Ptr transport_config(new TCPTransportServer::Config());
            transport_config->bind_addr = config_.bind_addr;
            transport_config->port = config_.port;
            transport_config->frame = frame_;
            transport_config->stats = stats_;
            transport_config->max_clients = config_.max_clients;
            transport_config->handshake_timeout = config_.tcp_handshake_timeout;
            transport_config->max_conns_per_addr = config_.tcp_max_conns_per_addr;
            transport_config->send_queue_max_packets = config_.tcp_send_queue_max_packets;
            transport_config->reap_interval = config_.reap_interval_seconds;

            transport_ = new TCPTransportServer::Server(*io_context_, transport_config, proto_factory);
        }
        else
        {
            UDPTransportServer::Config::Ptr transport_config(new UDPTransportServer::Config());
            transport_config->bind_addr = config_.bind_addr;
            transport_config->port = config_.port;
            transport_config->frame = frame_;
            transport_config->stats = stats_;
            transport_config->max_clients = config_.max_clients;
            transport_config->rcvbuf = config_.rcvbuf;
            transport_config->sndbuf = config_.sndbuf;
            transport_config->n_parallel = config_.n_parallel;
            transport_config->reap_interval = config_.reap_interval_seconds;

            UDPTransportServer::Server::Ptr udp_server(
                new UDPTransportServer::Server(*io_context_, transport_config, proto_factory));
            udp_transport_ = udp_server.get();
            transport_ = udp_server;
        }

        if (real_tun_device_)
            real_tun_device_->start(config_.n_parallel);
        transport_->start();
        if (dco_channel_)
            dco_channel_->set_transport_fd(udp_transport_->native_handle());

        running_.store(true);
        thread_ = std::thread([this]()
                              {
                                  const Log::Context log_context(logwrap_);
                                  try
                                  {
                                      io_context_->run();
                                  }
                                  catch (const std::exception &e)
                                  {
                                      fatal_error_ = e.what();
                                      OPENVPN_LOG("FATAL: unhandled exception on the server event loop: " << e.what());
                                  }
                                  catch (...)
                                  {
                                      fatal_error_ = "unknown exception";
                                      OPENVPN_LOG("FATAL: unhandled non-standard exception on the server event loop");
                                  } });
    }

    /**
     * @brief Roll back a partially-built @c start(), in reverse build order.
     * @details Everything here tolerates the corresponding step never having
     *  run, so this is safe to call from any point of the build.
     */
    void unwind_failed_start()
    {
        if (transport_)
            transport_->stop();
        transport_.reset();
        udp_transport_ = nullptr;
        net_policy_.shutdown();
        if (real_tun_device_)
            real_tun_device_->stop();
        real_tun_device_.reset();
        if (dco_channel_)
            dco_channel_->stop();
        dco_channel_.reset();
        routes_.reset();
        address_pool_.reset();
    }

  public:
    /** @brief Whether the server is currently running. */
    bool is_running() const
    {
        return running_.load();
    }

    /**
     * @brief What killed the event loop, if anything did.
     * @details Empty unless an exception escaped a handler and unwound
     *  @c io_context::run(). The loop does not come back after that: the
     *  server stops processing but @c is_running() stays @c true, so an
     *  embedder that wants to notice has to ask. That is the case this exists
     *  for, and it is readable exactly then -- the loop dying does not destroy
     *  the server. Reading it on a healthy server races the worker for no
     *  purpose; ask when the server has visibly gone quiet.
     * @return The exception's message, or an empty string.
     */
    const std::string &fatal_error() const
    {
        return fatal_error_;
    }

    /**
     * @brief Whether the kernel DCO datapath is actually active.
     * @details DCO is opportunistic (`Config::disable_dco`, matching OpenVPN
     *  2's own convention): even with it not disabled, `start()` may have
     *  silently fallen back to the classic path (module unavailable,
     *  incompatible cipher, ...). Only meaningful after `start()` returns.
     */
    bool is_dco_active() const
    {
        return static_cast<bool>(dco_channel_);
    }

  private:
    /**
     * @brief Verify every address the pool can hand out lies in the gateway's
     *  subnet.
     * @throws openvpn::Exception naming the first address that does not.
     */
    void check_pool_within_subnet() const
    {
        if (!config_.pool_size)
            return;

        const IP::Addr netmask = IP::Addr::netmask_from_prefix_len(config_.gateway.version(),
                                                                   config_.prefix_len);
        const IP::Addr network = config_.gateway & netmask;
        const IP::Addr last = config_.pool_start + static_cast<long>(config_.pool_size - 1);

        for (const IP::Addr &edge : {config_.pool_start, last})
        {
            if ((edge & netmask) != network)
                throw Exception("address pool " + config_.pool_start.to_string() + "+"
                                + std::to_string(config_.pool_size) + " leaves the "
                                + network.to_string() + "/" + std::to_string(config_.prefix_len)
                                + " subnet at " + edge.to_string());
        }
    }

    /**
     * @brief Build the shared protocol configuration from @c config_.
     * @return A fully populated protocol configuration.
     * @throws openvpn::Exception if PKI content cannot be parsed.
     */
    ProtoContext::ProtoConfig::Ptr build_proto_config()
    {
        StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());

        SSLLib::SSLAPI::Config::Ptr ssl(new SSLLib::SSLAPI::Config());
        ssl->set_mode(Mode(Mode::SERVER));
        ssl->set_frame(frame_);
        ssl->set_rng(rng);
        ssl->load_ca(config_.ca, true);
        ssl->load_cert(config_.cert);
        ssl->load_private_key(config_.key);
        if (!config_.dh.empty())
            ssl->load_dh(config_.dh);
        if (!config_.crl.empty())
            ssl->load_crl(config_.crl);
        if (config_.client_cert_optional)
            ssl->set_flags(SSLConst::PEER_CERT_OPTIONAL);
        ssl->set_tls_version_min(TLSVersion::Type::V1_2);

        ProtoContext::ProtoConfig::Ptr pc(new ProtoContext::ProtoConfig());
        pc->ssl_factory = ssl->new_factory();

        CryptoAlgs::allow_default_dc_algs<SSLLib::CryptoAPI>(pc->ssl_factory->libctx(), false, false);

        pc->dc.set_factory(new CryptoDCSelect<SSLLib::CryptoAPI>(pc->ssl_factory->libctx(), frame_, stats_, rng));
        pc->tlsprf_factory.reset(new CryptoTLSPRFFactory<SSLLib::CryptoAPI>());
        pc->frame = frame_;
        pc->now = &now_;
        pc->rng = rng;
        pc->prng = rng;
        pc->protocol = config_.proto;
        pc->layer = Layer(Layer::OSI_LAYER_3);
        pc->dc.set_cipher(CryptoAlgs::lookup(config_.cipher));
        pc->dc.set_digest(CryptoAlgs::lookup("SHA256"));
        pc->enable_op32 = true;
        pc->dc_deferred = true;
        pc->keepalive_ping = Time::Duration::seconds(config_.keepalive_ping);
        pc->keepalive_timeout = Time::Duration::seconds(config_.keepalive_timeout);
        pc->keepalive_timeout_early = pc->keepalive_timeout;
        pc->handshake_window = Time::Duration::seconds(60);
        pc->tls_timeout = Time::Duration::seconds(1);
        pc->renegotiate = Time::Duration::seconds(config_.renegotiate_seconds) + pc->handshake_window;
        pc->expire = pc->renegotiate + pc->renegotiate;
        const int tls_wrappers = static_cast<int>(!config_.tls_auth.empty())
                                 + static_cast<int>(!config_.tls_crypt.empty())
                                 + static_cast<int>(!config_.tls_crypt_v2.empty());
        if (tls_wrappers > 1)
            throw Exception("at most one of tls_auth, tls_crypt, tls_crypt_v2 may be set");

        if (!config_.tls_auth.empty())
        {
            pc->tls_auth_factory.reset(new CryptoOvpnHMACFactory<SSLLib::CryptoAPI>());
            pc->tls_auth_key.parse(config_.tls_auth);
            pc->set_tls_auth_digest(CryptoAlgs::lookup("SHA1"));
            pc->key_direction = config_.tls_auth_key_direction;
        }
        else if (!config_.tls_crypt.empty())
        {
            pc->tls_crypt_factory.reset(new CryptoTLSCryptFactory<SSLLib::CryptoAPI>());
            pc->tls_crypt_key.parse(config_.tls_crypt);
            pc->set_tls_crypt_algs();
            pc->tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V1;
        }
        else if (!config_.tls_crypt_v2.empty())
        {
            pc->tls_crypt_factory.reset(new CryptoTLSCryptFactory<SSLLib::CryptoAPI>());
            TLSCryptV2ServerKey server_key;
            server_key.parse(config_.tls_crypt_v2);
            server_key.extract_key(pc->tls_crypt_key);
            pc->set_tls_crypt_algs();
            pc->tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V2;
        }

        return pc;
    }

    Config config_;
    Handler &handler_;

    // Must outlive every SSL object built in start()
    InitProcess::Init init_;
    Log::Context::Wrapper logwrap_;

    Time now_;
    Frame::Ptr frame_;
    SessionStats::Ptr stats_;

    // Declared before every member that owns an asio object
    std::unique_ptr<openvpn_io::io_context> io_context_;

    std::unique_ptr<PeerRoutes::AddressPool> address_pool_;
    std::unique_ptr<PeerRoutes::RouteTable> routes_;
    TunReal::Device::Ptr real_tun_device_;
    DcoServ::Channel::Ptr dco_channel_;
    NetPolicy::Policy net_policy_;
    TransportServer::Ptr transport_;

    // Non-owning view of transport_ when it is the UDP server, else null.
    UDPTransportServer::Server *udp_transport_ = nullptr;
    std::thread thread_;
    std::atomic<bool> running_{false};

    /** Set by @c start(); never cleared, since a server runs at most once. */
    bool started_ = false;

    std::string fatal_error_;
};

} // namespace openvpn::ServerAPI

#endif
