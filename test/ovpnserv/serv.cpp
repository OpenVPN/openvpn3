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
 * @brief Reference OpenVPN 3 server binary: classic (non-DCO) userspace data
 *  path, built on `ServerAPI::OpenVPNServer`.
 *
 * @details
 * This binary is now a thin consumer of `openvpn/server_api/openvpn_server.hpp`
 * -- the same relationship `test/ovpncli/cli.cpp` has to
 * `ClientAPI::OpenVPNClient` -- rather than wiring the protocol/transport/tun
 * layers together itself. Its only remaining job is command-line parsing,
 * reading PKI files into the PEM content strings `ServerAPI::Config` expects,
 * defining a concrete `ReferenceHandler` (accepts every client -- **this
 * binary authenticates no one and must not be deployed**), and translating a
 * process signal into `OpenVPNServer::stop()`.
 *
 * Usage:
 * @code
 *   ovpnserv --ca ca.crt --cert server.crt --key server.key [options]
 * @endcode
 *
 * @note Bringing up a real TUN device requires @c CAP_NET_ADMIN.
 */

#include <cstdlib>
#include <iostream>
#include <string>

#include <openvpn/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_WIN
#error "ovpnserv is Linux/Unix only"
#endif

// Must precede every core header: they expand OPENVPN_LOG at parse time.
#include <openvpn/log/logbasesimple.hpp>

#include <openvpn/io/io.hpp>

#include <openvpn/asio/asiosignal.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>

#include "servconf.hpp"
#include <openvpn/server_api/openvpn_server.hpp>

using namespace openvpn;
using namespace openvpn::ServerAPI;
using namespace openvpn::ovpnserv;

/**
 * @brief Command-line configuration for the reference server.
 */
struct ServerArgs
{
    std::string ca_file;
    std::string cert_file;
    std::string key_file;
    std::string dh_file;
    std::string crl_file;
    std::string tls_auth_file;
    std::string tls_crypt_file;
    std::string tls_crypt_v2_file;
    std::string bind_addr = "0.0.0.0";
    unsigned short port = 1194;
    std::string cipher = "AES-256-GCM";
    std::string gateway = "10.8.0.1";
    std::string pool_start = "10.8.0.2";
    unsigned int pool_size = 252;
    unsigned int prefix_len = 24;
    unsigned int keepalive_ping = 10;
    unsigned int keepalive_timeout = 60;
    int key_direction = 0;
    unsigned int reneg_sec = 3600;
    unsigned int rcvbuf = 0;
    unsigned int sndbuf = 0;
    std::string tun_name; // empty lets the kernel assign one
    unsigned int tun_mtu = 1500;
    std::string config_file;    // --config; mutually exclusive with the rest
    std::set<std::string> seen; // flags actually supplied, for conflict reporting
    bool tcp = false;           // outer transport; UDP by default
    unsigned int tcp_handshake_timeout = 30;
    unsigned int tcp_max_conns_per_addr = 8;
    unsigned int tcp_send_queue_max_packets = 1024;
    bool null_tun = false;             // control-plane-only diagnostic mode, see tunsink.hpp
    bool client_to_client = false;     // off by default; enforced by netpolicy.hpp
    bool client_cert_optional = false; // off by default, matches OpenVPN 2

    // Kernel DCO is attempted opportunistically by default (see dcoserv.hpp),
    // matching OpenVPN 2's own --disable-dco convention: opt-out, not opt-in.
    bool disable_dco = false;

    // Perf / limits; defaults mirror ServerAPI::Config's own defaults.
    std::size_t max_clients = 1024;
    int n_parallel = 4;
    unsigned int reap_interval = 5;

    // 0 keeps on_stats() unwired, matching ServerAPI::Config's default.
    unsigned int stats_interval = 0;
};

/**
 * @brief Print command-line usage to stderr.
 * @param argv0 The program name as invoked.
 */
static void usage(const char *argv0)
{
    std::cerr
        << "usage: " << argv0 << " --ca FILE --cert FILE --key FILE [options]\n"
        << "\n"
        << "  --config FILE        read OpenVPN-style directives from FILE instead of\n"
        << "                       flags; may not be combined with other options\n"
        << "  --ca FILE            CA certificate bundle (required unless --config)\n"
        << "  --cert FILE          server certificate (required unless --config)\n"
        << "  --key FILE           server private key (required unless --config)\n"
        << "  --dh FILE            Diffie-Hellman parameters\n"
        << "  --crl-verify FILE    CRL bundle; rejects a peer cert it revokes\n"
        << "  --tls-auth FILE      tls-auth static key (enables the psid cookie gate)\n"
        << "  --tls-crypt FILE     tls-crypt v1 static key\n"
        << "  --tls-crypt-v2 FILE  tls-crypt-v2 server key (single key, no by-ID\n"
        << "                       rotation directory)\n"
        << "                       at most one of --tls-auth/--tls-crypt/--tls-crypt-v2\n"
        << "  --key-direction N    tls-auth key direction, default 0\n"
        << "  --client-cert-optional  allow a client with no certificate (auth-user-pass\n"
        << "                       only) to connect, off by default\n"
        << "  --bind ADDR          listen address, default 0.0.0.0\n"
        << "  --port N             listen port, default 1194\n"
        << "  --cipher ALG         data-channel cipher, default AES-256-GCM\n"
        << "  --gateway ADDR       tunnel gateway, default 10.8.0.1\n"
        << "  --pool-start ADDR    first client address, default 10.8.0.2\n"
        << "  --pool-size N        number of pool addresses, default 252\n"
        << "  --prefix-len N       tunnel prefix length, default 24\n"
        << "  --keepalive P T      ping interval and timeout, default 10 60\n"
        << "  --reneg-sec N        data-channel key renegotiation interval, default 3600\n"
        << "  --rcvbuf N           socket receive buffer bytes\n"
        << "  --sndbuf N           socket send buffer bytes\n"
        << "  --proto udp|tcp      outer transport, default udp (tcp forces the\n"
        << "                       classic data path: no kernel DCO over TCP)\n"
        << "  --handshake-timeout N  tcp: seconds a connection may stay open without\n"
        << "                       a validated first packet, default 30, 0 disables\n"
        << "  --max-conns-per-addr N tcp: concurrent connections per source address,\n"
        << "                       default 8, 0 disables\n"
        << "  --send-queue-max-packets N\n"
        << "                       tcp: queued outbound packets per connection before\n"
        << "                       it is dropped, default 1024, 0 disables\n"
        << "  --max-clients N      maximum concurrent sessions, default 1024\n"
        << "  --n-parallel N       parallel session-handling slots, default 4\n"
        << "  --reap-interval N    idle-session reap interval seconds, default 5\n"
        << "  --stats-interval N   log aggregate server stats every N seconds, default 0\n"
        << "                       (0 disables reporting entirely)\n"
        << "  --tun-name NAME      requested tun (or DCO netdev) device name, default\n"
        << "                       kernel-assigned\n"
        << "  --tun-mtu N          tun device MTU, default 1500\n"
        << "  --null-tun           discard payload instead of opening a real tun device\n"
        << "                       (control-plane-only diagnostic mode)\n"
        << "  --client-to-client   allow traffic between connected clients' tunnel\n"
        << "                       addresses, off by default (classic tun datapath only --\n"
        << "                       no policy seam under kernel DCO, see dcoserv.hpp)\n"
        << "  --disable-dco        do not attempt the kernel DCO datapath; use a\n"
        << "                       userspace tun device even if DCO is available\n"
        << "\n"
        << "This server accepts every client that completes the TLS handshake.\n"
        << "It is a reference/test harness, not a production server.\n";
}

/**
 * @brief Parse command-line arguments.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param[out] args Populated on success.
 * @return True if parsing succeeded and required options were supplied.
 */
static bool parse_args(int argc, char *argv[], ServerArgs &args)
{
    for (int i = 1; i < argc; ++i)
    {
        const std::string opt = argv[i];
        auto next = [&](const char *what) -> std::string
        {
            if (i + 1 >= argc)
                throw Exception(std::string("missing argument to ") + what);
            return argv[++i];
        };

        if (opt.starts_with("--"))
            args.seen.insert(opt);

        if (opt == "--ca")
            args.ca_file = next("--ca");
        else if (opt == "--cert")
            args.cert_file = next("--cert");
        else if (opt == "--key")
            args.key_file = next("--key");
        else if (opt == "--dh")
            args.dh_file = next("--dh");
        else if (opt == "--crl-verify")
            args.crl_file = next("--crl-verify");
        else if (opt == "--tls-auth")
            args.tls_auth_file = next("--tls-auth");
        else if (opt == "--tls-crypt")
            args.tls_crypt_file = next("--tls-crypt");
        else if (opt == "--tls-crypt-v2")
            args.tls_crypt_v2_file = next("--tls-crypt-v2");
        else if (opt == "--key-direction")
            args.key_direction = std::stoi(next("--key-direction"));
        else if (opt == "--client-cert-optional")
            args.client_cert_optional = true;
        else if (opt == "--bind")
            args.bind_addr = next("--bind");
        else if (opt == "--port")
            args.port = static_cast<unsigned short>(std::stoi(next("--port")));
        else if (opt == "--cipher")
            args.cipher = next("--cipher");
        else if (opt == "--gateway")
            args.gateway = next("--gateway");
        else if (opt == "--pool-start")
            args.pool_start = next("--pool-start");
        else if (opt == "--pool-size")
            args.pool_size = static_cast<unsigned int>(std::stoi(next("--pool-size")));
        else if (opt == "--prefix-len")
            args.prefix_len = static_cast<unsigned int>(std::stoi(next("--prefix-len")));
        else if (opt == "--keepalive")
        {
            args.keepalive_ping = static_cast<unsigned int>(std::stoi(next("--keepalive")));
            args.keepalive_timeout = static_cast<unsigned int>(std::stoi(next("--keepalive")));
        }
        else if (opt == "--reneg-sec")
            args.reneg_sec = static_cast<unsigned int>(std::stoi(next("--reneg-sec")));
        else if (opt == "--rcvbuf")
            args.rcvbuf = static_cast<unsigned int>(std::stoi(next("--rcvbuf")));
        else if (opt == "--sndbuf")
            args.sndbuf = static_cast<unsigned int>(std::stoi(next("--sndbuf")));
        else if (opt == "--max-clients")
            args.max_clients = static_cast<std::size_t>(std::stoul(next("--max-clients")));
        else if (opt == "--n-parallel")
            args.n_parallel = std::stoi(next("--n-parallel"));
        else if (opt == "--reap-interval")
            args.reap_interval = static_cast<unsigned int>(std::stoi(next("--reap-interval")));
        else if (opt == "--stats-interval")
            args.stats_interval = static_cast<unsigned int>(std::stoi(next("--stats-interval")));
        else if (opt == "--tun-name")
            args.tun_name = next("--tun-name");
        else if (opt == "--tun-mtu")
            args.tun_mtu = static_cast<unsigned int>(std::stoi(next("--tun-mtu")));
        else if (opt == "--config")
            args.config_file = next("--config");
        else if (opt == "--proto")
        {
            const std::string proto = next("--proto");
            if (proto == "tcp" || proto == "tcp-server")
                args.tcp = true;
            else if (proto == "udp")
                args.tcp = false;
            else
                throw Exception("--proto must be udp or tcp, got: " + proto);
        }
        else if (opt == "--handshake-timeout")
            args.tcp_handshake_timeout = static_cast<unsigned int>(std::stoi(next("--handshake-timeout")));
        else if (opt == "--max-conns-per-addr")
            args.tcp_max_conns_per_addr = static_cast<unsigned int>(std::stoi(next("--max-conns-per-addr")));
        else if (opt == "--send-queue-max-packets")
            args.tcp_send_queue_max_packets = static_cast<unsigned int>(std::stoi(next("--send-queue-max-packets")));
        else if (opt == "--null-tun")
            args.null_tun = true;
        else if (opt == "--client-to-client")
            args.client_to_client = true;
        else if (opt == "--disable-dco")
            args.disable_dco = true;
        else if (opt == "--help" || opt == "-h")
            return false;
        else
            throw Exception("unrecognized option: " + opt);
    }

    if (!args.config_file.empty())
    {
        std::string conflicts;
        for (const std::string &flag : args.seen)
            if (flag != "--config")
                conflicts += (conflicts.empty() ? "" : " ") + flag;
        if (!conflicts.empty())
            throw Exception("--config may not be combined with other options, but got: "
                            + conflicts);
        return true;
    }

    return !(args.ca_file.empty() || args.cert_file.empty() || args.key_file.empty());
}

/**
 * @brief Build a `ServerAPI::Config` from parsed command-line arguments.
 * @param args Parsed command line.
 * @return A config with every PKI field populated from file content (see
 *  `server_api.hpp`'s file doc comment for why content, not paths).
 * @throws openvpn::Exception if a key or certificate file cannot be read.
 */
static Config build_config(const ServerArgs &args)
{
    if (!args.config_file.empty())
    {
        Config config;
        std::vector<std::string> ignored;
        ServConf::apply_file(args.config_file, config, ignored);
        if (!ignored.empty())
        {
            std::string list;
            for (const std::string &name : ignored)
                list += (list.empty() ? "" : ", ") + name;
            OPENVPN_LOG("config: accepted and ignored (no effect on this binary): " << list);
        }
        return config;
    }

    Config config;
    config.bind_addr = args.bind_addr;
    config.port = args.port;
    config.ca = read_text_utf8(args.ca_file);
    config.cert = read_text_utf8(args.cert_file);
    config.key = read_text_utf8(args.key_file);
    if (!args.dh_file.empty())
        config.dh = read_text_utf8(args.dh_file);
    if (!args.crl_file.empty())
        config.crl = read_text_utf8(args.crl_file);
    if (!args.tls_auth_file.empty())
    {
        config.tls_auth = read_text_utf8(args.tls_auth_file);
        config.tls_auth_key_direction = args.key_direction;
    }
    if (!args.tls_crypt_file.empty())
        config.tls_crypt = read_text_utf8(args.tls_crypt_file);
    if (!args.tls_crypt_v2_file.empty())
        config.tls_crypt_v2 = read_text_utf8(args.tls_crypt_v2_file);
    config.client_cert_optional = args.client_cert_optional;
    config.cipher = args.cipher;
    config.renegotiate_seconds = args.reneg_sec;
    config.gateway = IP::Addr::from_string(args.gateway, "gateway");
    config.pool_start = IP::Addr::from_string(args.pool_start, "pool-start");
    config.pool_size = args.pool_size;
    config.prefix_len = args.prefix_len;
    config.keepalive_ping = args.keepalive_ping;
    config.keepalive_timeout = args.keepalive_timeout;
    config.tun_name = args.tun_name;
    config.tun_mtu = args.tun_mtu;
    config.null_tun = args.null_tun;
    config.client_to_client = args.client_to_client;
    config.disable_dco = args.disable_dco;
    config.proto = args.tcp ? Protocol(Protocol::TCPv4) : Protocol(Protocol::UDPv4);
    config.tcp_handshake_timeout = args.tcp_handshake_timeout;
    config.tcp_max_conns_per_addr = args.tcp_max_conns_per_addr;
    config.tcp_send_queue_max_packets = args.tcp_send_queue_max_packets;
    config.rcvbuf = args.rcvbuf;
    config.sndbuf = args.sndbuf;
    config.max_clients = args.max_clients;
    config.n_parallel = args.n_parallel;
    config.reap_interval_seconds = args.reap_interval;
    config.stats_interval_seconds = args.stats_interval;
    return config;
}

/**
 * @brief Reference event handler: accepts every client that completes the
 *  TLS handshake and logs connection lifecycle events.
 * @details **Authenticates no one.** A real embedder makes an actual
 *  decision in `on_client_auth` (credential check, external call, ...)
 *  instead of allowing unconditionally.
 */
class ReferenceHandler
{
  public:
    void on_client_auth(const AuthRequest &req, AuthDecision decision)
    {
        OPENVPN_LOG("auth request: cn=" << req.common_name
                                        << " user=" << req.username
                                        << " from=" << req.transport_info);
        decision.allow();
    }

    void on_client_connected(const ClientInfo &client)
    {
        OPENVPN_LOG("client connected: " << client.common_name
                                         << " " << client.vpn_address
                                         << " from " << client.transport_info);
    }

    void on_client_disconnected(const ClientInfo &client, DisconnectReason reason)
    {
        OPENVPN_LOG("client disconnected: " << client.common_name << " reason=" << to_string(reason));
    }

    void on_stats(const ServerStats &stats)
    {
        OPENVPN_LOG("stats: " << stats.connected_clients << " clients, "
                              << stats.total_rx_bytes << " rx, " << stats.total_tx_bytes << " tx");
    }
};

static_assert(ServerEventHandler<ReferenceHandler>);

/**
 * @brief Program entry point: build the server, run it, and stop on signal.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on clean shutdown, 1 on error or usage failure.
 */
int main(int argc, char *argv[])
{
    ServerArgs args;

    try
    {
        if (!parse_args(argc, argv, args))
        {
            usage(argv[0]);
            return 1;
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "error: " << e.what() << "\n\n";
        usage(argv[0]);
        return 1;
    }

    try
    {
        // Installs itself as the process log sink; OPENVPN_LOG output goes
        // nowhere until this exists.
        LogBaseSimple log;

        const Config config = build_config(args);
        ReferenceHandler handler;
        OpenVPNServer<ReferenceHandler> server(config, handler);

        server.start();
        const char *data_path = server.is_dco_active() ? ", kernel DCO data path" : config.null_tun ? ", null data path"
                                                                                                    : ", real tun device";
        // From config, not args: with --config the argv fields are untouched, and
        // reporting their defaults would contradict the listener that just came up.
        OPENVPN_LOG("ovpnserv: listening on " << config.bind_addr << ":" << config.port
                                              << (config.proto.is_tcp() ? " tcp" : " udp")
                                              << data_path << ", auth disabled");

        // The server runs on its own internal thread once start() returns.
        // This thread waits for a signal; consuming it leaves this io_context
        // with no work, run() returns, and the server's destructor stops and
        // joins on the way out. Deliberately no stop() call here: a server is
        // stopped by its own destruction and by nothing else, which is what
        // keeps "which thread may stop it" from being a question at all.
        openvpn_io::io_context signal_io_context(1);
        ASIOSignals signals(signal_io_context);
        signals.register_signals_all(
            [&](const openvpn_io::error_code &error, int signum)
            {
                if (!error)
                    OPENVPN_LOG("signal " << signum << ", shutting down");
            });
        signal_io_context.run();

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "fatal: " << e.what() << std::endl;
        return 1;
    }
}
