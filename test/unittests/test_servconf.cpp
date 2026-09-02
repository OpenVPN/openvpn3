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

// Unit tests for the reference server binary's config-file mapping
// (test/ovpnserv/servconf.hpp).
//
// These use inline PKI blocks throughout, so nothing here touches the
// filesystem: the mapping from directives to ServerAPI::Config is the thing
// under test, and the file-reading path is covered by the integration test that
// drives a real v2-style config with `ca <path>` form.
//
// The refusal cases carry most of the value. A config parser that silently
// drops a directive an operator wrote is worse than one that rejects the file,
// because the operator ends up believing they configured something they did
// not -- so "unknown directive throws" is a behavioural guarantee, not a
// nicety.

#include "test_common.hpp"
#include "test_generators.hpp"

#include <cstdint>
#include <optional>

#include <openvpn/addr/ip.hpp>
#include <openvpn/common/options.hpp>

#include "../ovpnserv/servconf.hpp"

using namespace openvpn;
using namespace openvpn::ovpnserv;

namespace {

// Minimal PKI so `apply()` sees the directives it expects; content is never
// parsed by the mapping itself.
const char *const INLINE_PKI = R"(
<ca>
-----BEGIN CERTIFICATE-----
not-a-real-cert
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
also-not-real
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
still-not-real
-----END PRIVATE KEY-----
</key>
)";

// Parse directive text and map it, returning the resulting config.
// Usage: apply_text("proto tcp\n", ignored_out)
ServerAPI::Config apply_text(const std::string &text, std::vector<std::string> &ignored)
{
    OptionList opt;
    opt.parse_from_config(std::string(INLINE_PKI) + text, nullptr);
    opt.update_map();
    ServerAPI::Config config;
    ServConf::apply(opt, std::string(), config, ignored);
    return config;
}

ServerAPI::Config apply_text(const std::string &text)
{
    std::vector<std::string> ignored;
    return apply_text(text, ignored);
}

} // namespace

TEST(ServConf, InlinePkiIsUsedVerbatim)
{
    const ServerAPI::Config config = apply_text("");
    ASSERT_NE(config.ca.find("not-a-real-cert"), std::string::npos);
    ASSERT_NE(config.cert.find("also-not-real"), std::string::npos);
    ASSERT_NE(config.key.find("still-not-real"), std::string::npos);
}

TEST(ServConf, ServerDirectiveDerivesGatewayAndPool)
{
    const ServerAPI::Config config = apply_text("server 10.20.0.0 255.255.255.0\n");
    ASSERT_EQ(config.gateway.to_string(), "10.20.0.1");
    ASSERT_EQ(config.pool_start.to_string(), "10.20.0.2");
    ASSERT_EQ(config.prefix_len, 24u);
    // /24 less network, gateway and broadcast -- matches OpenVPN 2's pool with
    // topology subnet, which runs to .254.
    ASSERT_EQ(config.pool_size, 253u);
}

TEST(ServConf, ServerDirectiveHonoursNarrowerMask)
{
    const ServerAPI::Config config = apply_text("server 10.30.0.0 255.255.255.128\n");
    ASSERT_EQ(config.gateway.to_string(), "10.30.0.1");
    ASSERT_EQ(config.prefix_len, 25u);
    ASSERT_EQ(config.pool_size, 125u);
}

// A /30 is the narrowest usable server subnet: network, gateway, one client,
// broadcast. Anything narrower has no client address at all.
TEST(ServConf, ServerDirectiveAcceptsTheNarrowestUsableMask)
{
    const ServerAPI::Config config = apply_text("server 10.40.0.0 255.255.255.252\n");
    ASSERT_EQ(config.gateway.to_string(), "10.40.0.1");
    ASSERT_EQ(config.pool_start.to_string(), "10.40.0.2");
    ASSERT_EQ(config.pool_size, 1u);
}

TEST(ServConf, ServerDirectiveRejectsAMaskWithNoRoom)
{
    ASSERT_THROW(apply_text("server 10.40.0.0 255.255.255.254\n"), Exception);
    ASSERT_THROW(apply_text("server 10.40.0.0 255.255.255.255\n"), Exception);
}

/// PROPERTY: for any prefix length a client pool fits in, a `server` directive whose netmask is an IPv6 address is rejected.
/// @warning Expected to FAIL against current production: ServConf::apply_server_directive checks
///  the version of the network but not of the netmask, so an IPv6 mask yields an IPv4 pool.
RC_GTEST_PROP(ServConf, ServerDirectiveRejectsANonIPv4Netmask, ())
{
    // Capped at 30 so apply_server_directive's own "no room for a client pool"
    // guard cannot fire: the rejection under test is the family, not the width.
    const auto prefix_len = *rc::gen::inRange<unsigned int>(0, 31).as("netmask prefix length");
    const IP::Addr netmask = IP::Addr::netmask_from_prefix_len(IP::Addr::V6, prefix_len);

    // The diagnostic has to name the netmask: the sibling check on the network argument
    // reports the offending address, and a bare throw would not tell the two apart.
    std::optional<std::string> rejection;
    try
    {
        apply_text("server 10.20.0.0 " + netmask.to_string() + "\n");
    }
    catch (const Exception &e)
    {
        rejection = e.what();
    }

    RC_ASSERT(rejection.has_value());
    RC_ASSERT(rejection->find(netmask.to_string()) != std::string::npos); // NOLINT(bugprone-unchecked-optional-access)
}

/// PROPERTY: for any usable IPv4 server netmask, the mapped pool size is the subnet's address count less the network, gateway and broadcast addresses.
RC_GTEST_PROP(ServConf, ServerDirectivePoolSizeFollowsTheMaskForEveryUsablePrefix, ())
{
    // /16 is the narrowest the directive accepts, following OpenVPN 2; 10.20.0.0 is also
    // its own subnet's network address from /14 up, so the whole range is usable here.
    const auto prefix_len = *rc::gen::inRange<unsigned int>(16, 31).as("netmask prefix length");
    const IP::Addr netmask = IP::Addr::netmask_from_prefix_len(IP::Addr::V4, prefix_len);

    const ServerAPI::Config config =
        apply_text("server 10.20.0.0 " + netmask.to_string() + "\n");

    // The extent is read off the subnet's own endpoints rather than recomputed from the
    // prefix, so neither the count nor the number of reserved addresses is copied from the
    // mapper: the pool runs from the first address it hands out up to the one before the
    // subnet's last address, which the directive reserves as the broadcast address.
    const IP::Addr network = IP::Addr::from_string("10.20.0.0");
    const IP::Addr broadcast = network | ~netmask;
    const std::uint64_t first = ntohl(config.pool_start.to_uint32_net());
    const std::uint64_t last = std::uint64_t(ntohl(broadcast.to_uint32_net())) - 1;

    RC_ASSERT(config.pool_start == network + 2);
    RC_ASSERT(std::uint64_t(config.pool_size) == (last - first) + 1);
}

/// PROPERTY: the pool a `server` directive derives never extends past its subnet's last address.
/// @details Previously failed: the pool was sized from the netmask but the gateway and pool
///  start came from the network argument unmasked, so a network that is not its subnet's own
/// PROPERTY: a network argument that is not its subnet's own network address is refused.
/// @details Previously accepted and mis-sized: the pool was sized from the netmask but the
///  gateway and pool start came from the argument unmasked, so the pool ran past the end of
///  its own subnet. Masking the argument instead would silently relocate the operator's pool,
///  so this refuses the pair as OpenVPN 2 does.
RC_GTEST_PROP(ServConf, ServerDirectiveRejectsANonNetworkAddress, ())
{
    // 10.20.0.0's lowest set bit is at index 13, so for any shorter prefix it is an interior
    // address of its subnet rather than the network address.
    const auto prefix_len = *rc::gen::inRange<unsigned int>(0, 14).as("netmask prefix length");
    const IP::Addr netmask = IP::Addr::netmask_from_prefix_len(IP::Addr::V4, prefix_len);

    std::optional<std::string> rejection;
    try
    {
        apply_text("server 10.20.0.0 " + netmask.to_string() + "\n");
    }
    catch (const Exception &e)
    {
        rejection = e.what();
    }

    RC_ASSERT(rejection.has_value());
    // The diagnostic has to name the address the operator probably meant.
    const IP::Addr network = IP::Addr::from_string("10.20.0.0") & netmask;
    RC_ASSERT(rejection->find(network.to_string()) != std::string::npos); // NOLINT(bugprone-unchecked-optional-access)
}

TEST(ServConf, ProtoSelectsTheTransport)
{
    ASSERT_TRUE(apply_text("proto udp\n").proto.is_udp());
    ASSERT_TRUE(apply_text("proto tcp\n").proto.is_tcp());
    ASSERT_TRUE(apply_text("proto tcp-server\n").proto.is_tcp());
    // Default when the directive is absent.
    ASSERT_TRUE(apply_text("").proto.is_udp());
}

TEST(ServConf, ProtoRejectsIPv6AndNonsense)
{
    ASSERT_THROW(apply_text("proto udp6\n"), Exception);
    ASSERT_THROW(apply_text("proto sctp\n"), Exception);
}

TEST(ServConf, ListenerAndLimitsAreMapped)
{
    const ServerAPI::Config config = apply_text("local 10.0.0.5\n"
                                                "port 1195\n"
                                                "max-clients 64\n"
                                                "tun-mtu 1400\n"
                                                "keepalive 7 42\n"
                                                "reneg-sec 900\n");
    ASSERT_EQ(config.bind_addr, "10.0.0.5");
    ASSERT_EQ(config.port, 1195);
    ASSERT_EQ(config.max_clients, 64u);
    ASSERT_EQ(config.tun_mtu, 1400u);
    ASSERT_EQ(config.keepalive_ping, 7u);
    ASSERT_EQ(config.keepalive_timeout, 42u);
    ASSERT_EQ(config.renegotiate_seconds, 900u);
}

TEST(ServConf, PolicyFlagsAreMapped)
{
    ASSERT_FALSE(apply_text("").client_to_client);
    ASSERT_TRUE(apply_text("client-to-client\n").client_to_client);
    ASSERT_FALSE(apply_text("").disable_dco);
    ASSERT_TRUE(apply_text("disable-dco\n").disable_dco);
    ASSERT_TRUE(apply_text("verify-client-cert optional\n").client_cert_optional);
    ASSERT_FALSE(apply_text("verify-client-cert require\n").client_cert_optional);
}

// A server that always demands a client certificate must not quietly accept a
// config asking it not to.
TEST(ServConf, VerifyClientCertNoneIsRefused)
{
    ASSERT_THROW(apply_text("verify-client-cert none\n"), Exception);
}

TEST(ServConf, DevNamesADeviceOnlyWhenItIsNotABareType)
{
    ASSERT_TRUE(apply_text("dev tun\n").tun_name.empty());
    ASSERT_EQ(apply_text("dev tun7\n").tun_name, "tun7");
}

TEST(ServConf, DevTapIsRefused)
{
    ASSERT_THROW(apply_text("dev tap\n"), Exception);
}

TEST(ServConf, SingleCipherIsAcceptedFromEitherDirective)
{
    ASSERT_EQ(apply_text("cipher AES-128-GCM\n").cipher, "AES-128-GCM");
    ASSERT_EQ(apply_text("data-ciphers AES-128-GCM\n").cipher, "AES-128-GCM");
}

// The engine negotiates nothing, so a list would silently mean "the first one"
// or "some one" -- either is a surprise worth refusing.
TEST(ServConf, CipherListIsRefused)
{
    ASSERT_THROW(apply_text("data-ciphers AES-256-GCM:AES-128-GCM\n"), Exception);
}

TEST(ServConf, PushDirectivesAreCollectedInOrder)
{
    const ServerAPI::Config config = apply_text("push \"dhcp-option DNS 10.0.0.1\"\n"
                                                "push \"redirect-gateway def1\"\n");
    ASSERT_EQ(config.extra_push.size(), 2u);
    ASSERT_EQ(config.extra_push[0], "dhcp-option DNS 10.0.0.1");
    ASSERT_EQ(config.extra_push[1], "redirect-gateway def1");
}

TEST(ServConf, ModeAndTlsServerAreAccepted)
{
    ASSERT_NO_THROW(apply_text("mode server\ntls-server\n"));
}

TEST(ServConf, HarmlessDirectivesAreIgnoredAndReported)
{
    std::vector<std::string> ignored;
    apply_text("persist-key\npersist-tun\nverb 4\nstatus /tmp/x\n", ignored);
    ASSERT_EQ(ignored.size(), 4u);
    // Reported by name so nothing disappears without a trace.
    ASSERT_NE(std::find(ignored.begin(), ignored.end(), "persist-key"), ignored.end());
    ASSERT_NE(std::find(ignored.begin(), ignored.end(), "status"), ignored.end());
}

// The central guarantee: a directive that is neither implemented nor known to
// be inert stops the server rather than being dropped.
TEST(ServConf, UnknownDirectiveThrows)
{
    ASSERT_THROW(apply_text("duplicate-cn\n"), Exception);
    ASSERT_THROW(apply_text("client-config-dir /etc/ccd\n"), Exception);
    ASSERT_THROW(apply_text("auth-user-pass-verify /bin/true via-file\n"), Exception);
    ASSERT_THROW(apply_text("plugin /usr/lib/x.so\n"), Exception);
}

TEST(ServConf, KeyDirectionIsMappedAndBounded)
{
    ASSERT_EQ(apply_text("key-direction 1\n").tls_auth_key_direction, 1);
    ASSERT_THROW(apply_text("key-direction 7\n"), Exception);
}
