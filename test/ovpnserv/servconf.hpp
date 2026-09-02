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
 * @brief OpenVPN-style config file support for the reference server binary.
 *
 * @details
 * Maps a subset of OpenVPN 2 server directives onto @c ServerAPI::Config, so
 * `ovpnserv --config server.conf` works instead of a long argv line. Parsing
 * itself is core's existing @c OptionList::parse_from_config(), which is the
 * same parser the client uses for `.ovpn` profiles, so both file idioms work:
 *
 *   - `ca /etc/openvpn/ca.crt` -- a path, read from disk relative to the config
 *     file's own directory when not absolute (OpenVPN 2's idiom)
 *   - `<ca>...</ca>` -- inline PEM, used as-is (the `.ovpn` idiom)
 *
 * **An unrecognized directive is an error, not a warning.** That is the whole
 * safety argument for this file. A server config carries directives that decide
 * who gets in; silently skipping one an operator wrote means they believe they
 * have a control they do not have. Directives that genuinely cannot change this
 * binary's behaviour are listed in @c ignorable_directives() and skipped with a
 * summary line, so nothing disappears quietly either.
 *
 * Scope: this is the reference/test harness binary, not a deployable server --
 * `serv.cpp`'s own header says it authenticates no one. The directive set here
 * is deliberately the subset that maps onto capabilities the engine actually
 * has, and an operator handing it a full production `server.conf` should expect
 * to be told which directives are not implemented rather than have them
 * ignored. `_planning/o3-server/ovpn2-config-compat-audit.md` tracks the gap
 * list.
 */

#ifndef OPENVPN_OVPNSERV_SERVCONF_H
#define OPENVPN_OVPNSERV_SERVCONF_H

#include <cstdint>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/path.hpp>
#include <openvpn/server_api/server_api.hpp>
#include <openvpn/transport/protocol.hpp>

namespace openvpn::ovpnserv::ServConf {

/**
 * @brief Directives accepted and then ignored, with the reason they are safe.
 * @details Only directives that cannot change who connects or how traffic is
 *  protected belong here. Anything affecting authentication, crypto, routing or
 *  admission must be either implemented or rejected.
 * @return The ignorable directive names.
 */
inline const std::set<std::string> &ignorable_directives()
{
    static const std::set<std::string> ignorable = {
        "daemon",                // this binary runs in the foreground by design
        "explicit-exit-notify",  // server-side graceful shutdown is unconditional
        "group",                 // no privilege drop (tracked in the compat audit)
        "ifconfig-pool-persist", // no pool persistence; pool is per-process
        "log",                   // logging goes to stdout
        "log-append",            //   "
        "mute",                  // verbosity shaping, no behavioural effect
        "mute-replay-warnings",
        "persist-key", // no key reload path to persist across
        "persist-tun", // tun lifetime is the process lifetime
        "status",      // no status file (tracked in the compat audit)
        "status-version",
        "topology", // subnet topology is the only mode implemented, and is
                    // what the server pushes regardless
        "user",     // no privilege drop
        "verb",     // verbosity is fixed
        "writepid", // no pid file
    };
    return ignorable;
}

/**
 * @brief Resolve a directive's file argument against the config file's directory.
 * @param arg The path as written in the config file.
 * @param base_dir Directory holding the config file, for relative paths.
 * @return An absolute-or-cwd-relative path suitable for reading.
 */
inline std::string resolve_path(const std::string &arg, const std::string &base_dir)
{
    if (base_dir.empty() || path::is_fully_qualified(arg))
        return arg;
    return path::join(base_dir, arg);
}

/**
 * @brief Read a PKI blob given either inline content or a path.
 * @details @c OptionList marks an inline `<tag>` block as multiline, and its
 *  argument is then the content itself; otherwise the argument is a filename.
 * @param opt The option list.
 * @param name Directive name, e.g. @c "ca".
 * @param base_dir Directory holding the config file, for relative paths.
 * @return The PEM (or key) content, or an empty string when the directive is absent.
 * @throws openvpn::Exception if a referenced file cannot be read.
 */
inline std::string pki_blob(const OptionList &opt,
                            const std::string &name,
                            const std::string &base_dir)
{
    const Option *o = opt.get_ptr(name);
    if (!o)
        return std::string();

    const std::string arg = o->get(1, Option::MULTILINE);
    if (o->is_multiline())
        return arg;
    return read_text_utf8(resolve_path(arg, base_dir));
}

/**
 * @brief Apply an OpenVPN 2-style `server <network> <netmask>` directive.
 * @details Mirrors OpenVPN 2 with `topology subnet`: the server takes the first
 *  host address and the pool runs from the second to the last host address.
 *  Note this is intentionally wider than @c ovpnserv's own argv default, which
 *  stops one address short of the last host; matching v2 is the point of
 *  supporting the directive at all.
 * @param o The `server` option.
 * @param config Configuration to populate.
 * @throws openvpn::Exception if the network or netmask is unusable.
 */
inline void apply_server_directive(const Option &o, ServerAPI::Config &config)
{
    const IP::Addr network = IP::Addr::from_string(o.get(1, 64), "server network");
    const IP::Addr netmask = IP::Addr::from_string(o.get(2, 64), "server netmask");

    if (network.version() != IP::Addr::V4)
        throw Exception("server: IPv4-only data path, got " + network.to_string());
    if (netmask.version() != IP::Addr::V4)
        throw Exception("server: netmask must be IPv4, got " + netmask.to_string());

    // Matches OpenVPN 2, which refuses the pair outright rather than correcting it.
    if (network != (network & netmask))
        throw Exception("server: " + network.to_string() + " is not the network address of "
                        + netmask.to_string() + "; did you mean "
                        + (network & netmask).to_string() + "?");

    const unsigned int prefix_len = netmask.prefix_len();
    // Lower bound is OpenVPN 2's: anything wider is an implausible pool, and sizing
    // one would have AddressPool materialise an address per entry.
    if (prefix_len < 16)
        throw Exception("server: netmask " + netmask.to_string()
                        + " allows too many host addresses; use 255.255.0.0 (/16) or narrower");
    if (prefix_len > 30)
        throw Exception("server: netmask " + netmask.to_string()
                        + " leaves no room for a client pool");

    // Total addresses in the subnet, less the network address, the server's own
    // gateway address, and the broadcast address.
    const std::uint64_t total = std::uint64_t(1) << (32 - prefix_len);
    config.gateway = network + 1;
    config.prefix_len = prefix_len;
    config.pool_start = network + 2;
    config.pool_size = static_cast<unsigned int>(total - 3);
}

/**
 * @brief Translate a `proto` argument to a transport protocol.
 * @param arg The directive argument, e.g. @c "udp", @c "tcp-server".
 * @return The protocol to listen on.
 * @throws openvpn::Exception for anything but a plain UDP or TCP form.
 */
inline Protocol parse_proto(const std::string &arg)
{
    if (arg == "udp" || arg == "udp4" || arg == "udp-server")
        return Protocol(Protocol::UDPv4);
    if (arg == "tcp" || arg == "tcp4" || arg == "tcp-server")
        return Protocol(Protocol::TCPv4);
    if (arg == "udp6" || arg == "tcp6" || arg == "tcp6-server")
        throw Exception("proto " + arg + ": IPv6 transport is not implemented");
    throw Exception("proto " + arg + ": expected udp or tcp");
}

/**
 * @brief Populate a server configuration from OpenVPN-style directives.
 *
 * @details Every directive is either applied, listed in
 *  @c ignorable_directives(), or rejected by name. Values already set in
 *  @p config (from argv, or the struct's own defaults) are left alone unless a
 *  directive overrides them, so a config file can be combined with flags.
 *
 * @param opt Parsed directive list.
 * @param base_dir Directory holding the config file, for relative file paths.
 * @param config Configuration to populate.
 * @param[out] ignored Names of directives that were accepted and skipped.
 *
 * @throws openvpn::Exception on an unsupported directive, or on a directive
 *  whose argument cannot be used.
 */
inline void apply(const OptionList &opt,
                  const std::string &base_dir,
                  ServerAPI::Config &config,
                  std::vector<std::string> &ignored)
{
    // PKI
    if (const std::string ca = pki_blob(opt, "ca", base_dir); !ca.empty())
        config.ca = ca;
    if (const std::string cert = pki_blob(opt, "cert", base_dir); !cert.empty())
        config.cert = cert;
    if (const std::string key = pki_blob(opt, "key", base_dir); !key.empty())
        config.key = key;
    if (const std::string dh = pki_blob(opt, "dh", base_dir); !dh.empty())
        config.dh = dh;
    if (const std::string crl = pki_blob(opt, "crl-verify", base_dir); !crl.empty())
        config.crl = crl;
    if (const std::string ta = pki_blob(opt, "tls-auth", base_dir); !ta.empty())
        config.tls_auth = ta;
    if (const std::string tc = pki_blob(opt, "tls-crypt", base_dir); !tc.empty())
        config.tls_crypt = tc;
    if (const std::string tc2 = pki_blob(opt, "tls-crypt-v2", base_dir); !tc2.empty())
        config.tls_crypt_v2 = tc2;

    if (const Option *o = opt.get_ptr("key-direction"))
        config.tls_auth_key_direction = o->get_num<int>(1, 0, 0, 1);

    // Listener
    if (const Option *o = opt.get_ptr("proto"))
        config.proto = parse_proto(o->get(1, 32));
    if (const Option *o = opt.get_ptr("port"))
        config.port = o->get_num<unsigned short>(1, config.port, 1, 65535);
    if (const Option *o = opt.get_ptr("lport"))
        config.port = o->get_num<unsigned short>(1, config.port, 1, 65535);
    if (const Option *o = opt.get_ptr("local"))
        config.bind_addr = o->get(1, 128);

    // Tunnel topology
    if (const Option *o = opt.get_ptr("server"))
        apply_server_directive(*o, config);
    if (const Option *o = opt.get_ptr("tun-mtu"))
        config.tun_mtu = o->get_num<unsigned int>(1, config.tun_mtu, 68, 65535);

    // `dev tun` names a type, `dev tun3` names a device; only the latter is a
    // request for a specific netdev.
    if (const Option *o = opt.get_ptr("dev"))
    {
        const std::string dev = o->get(1, 64);
        if (dev != "tun" && dev != "tap")
            config.tun_name = dev;
        if (dev == "tap")
            throw Exception("dev tap: layer-2 is not implemented, use dev tun");
    }

    // Crypto. `data-ciphers` is a negotiable list in v2; this engine has one
    // cipher, so only a single-entry list is unambiguous.
    if (const Option *o = opt.get_ptr("cipher"))
        config.cipher = o->get(1, 64);
    if (const Option *o = opt.get_ptr("data-ciphers"))
    {
        const std::string list = o->get(1, 256);
        if (list.find(':') != std::string::npos)
            throw Exception("data-ciphers " + list
                            + ": this server negotiates no cipher list; name exactly one");
        config.cipher = list;
    }

    // Timing
    if (const Option *o = opt.get_ptr("keepalive"))
    {
        config.keepalive_ping = o->get_num<unsigned int>(1, config.keepalive_ping, 1, 86400);
        config.keepalive_timeout = o->get_num<unsigned int>(2, config.keepalive_timeout, 1, 86400);
    }
    if (const Option *o = opt.get_ptr("reneg-sec"))
        config.renegotiate_seconds =
            o->get_num<unsigned int>(1, config.renegotiate_seconds, 0, 86400 * 30);

    // Limits and policy
    if (const Option *o = opt.get_ptr("max-clients"))
        config.max_clients = o->get_num<std::size_t>(1, config.max_clients, 1, 1000000);
    if (opt.exists("client-to-client"))
        config.client_to_client = true;
    if (opt.exists("disable-dco"))
        config.disable_dco = true;
    if (const Option *o = opt.get_ptr("verify-client-cert"))
    {
        const std::string mode = o->get(1, 32);
        if (mode == "none")
            throw Exception("verify-client-cert none: this server always requires a "
                            "client certificate");
        config.client_cert_optional = (mode == "optional");
    }

    // Pushed options, verbatim.
    if (const auto *list = opt.get_index_ptr("push"))
        for (const size_t i : *list)
            config.extra_push.push_back(opt[i].get(1, 256));

    // Anything left is either knowingly ignorable or a refusal.
    std::set<std::string> handled = {
        "ca",
        "cert",
        "key",
        "dh",
        "crl-verify",
        "tls-auth",
        "tls-crypt",
        "tls-crypt-v2",
        "key-direction",
        "proto",
        "port",
        "lport",
        "local",
        "server",
        "tun-mtu",
        "dev",
        "cipher",
        "data-ciphers",
        "keepalive",
        "reneg-sec",
        "max-clients",
        "client-to-client",
        "disable-dco",
        "verify-client-cert",
        "push",
        // Not options in the behavioural sense: mode/tls-server merely assert
        // that this file describes a server, which this binary always is.
        "mode",
        "tls-server",
    };

    for (const Option &o : opt)
    {
        const std::string &name = o.get(0, 128);
        if (handled.count(name))
            continue;
        if (ignorable_directives().count(name))
        {
            ignored.push_back(name);
            continue;
        }
        throw Exception("unsupported directive '" + name
                        + "': ovpnserv is a reference harness and refuses directives it "
                          "cannot honour rather than ignoring them. Remove it, or see "
                          "_planning/o3-server/ovpn2-config-compat-audit.md");
    }
}

/**
 * @brief Parse a config file and populate a server configuration from it.
 * @param path Path to the config file.
 * @param config Configuration to populate; existing values act as defaults.
 * @param[out] ignored Names of directives that were accepted and skipped.
 * @throws openvpn::Exception if the file cannot be read or a directive is
 *  unsupported.
 */
inline void apply_file(const std::string &path,
                       ServerAPI::Config &config,
                       std::vector<std::string> &ignored)
{
    const std::string text = read_text_utf8(path);
    OptionList opt;
    opt.parse_from_config(text, nullptr);
    opt.update_map();
    apply(opt, path::dirname(path), config, ignored);
}

} // namespace openvpn::ovpnserv::ServConf

#endif
