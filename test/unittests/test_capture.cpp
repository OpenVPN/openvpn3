//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2019- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#include "test_common.hpp"
#include "test_generators.hpp"

#include <iostream>

#include <openvpn/common/file.hpp>
#include <openvpn/tun/builder/capture.hpp>

using namespace openvpn;

TEST(misc, capture)
{
    DnsServer server;
    server.addresses = {DnsAddress("8.8.8.8"), DnsAddress("8.8.4.4:53")};
    DnsOptions dns_options;
    dns_options.servers[0] = std::move(server);
    dns_options.search_domains = {DnsDomain("yonan.net"), DnsDomain("openvpn.net")};

    TunBuilderCapture::Ptr tbc(new TunBuilderCapture);

    tbc->tun_builder_set_remote_address("52.7.171.249", false);
    tbc->tun_builder_add_address("1.2.3.4", 24, "10.10.0.1", false, false);
    tbc->tun_builder_add_address("fe80::c32:4ff:febf:97d9", 64, "9999::7777", true, false);
    tbc->tun_builder_reroute_gw(true, false, 123);
    tbc->tun_builder_add_route("192.168.0.0", 16, 33, false);
    tbc->tun_builder_add_route("10.0.0.0", 8, -1, false);
    tbc->tun_builder_add_route("2000::", 4, 55, true);
    // tbc->tun_builder_add_route("X000::", 4, -1, true); // fixme
    tbc->tun_builder_add_route("3000::", 4, -1, true);
    tbc->tun_builder_add_route("fc00::", 7, 66, true);
    tbc->tun_builder_exclude_route("10.10.0.0", 24, 77, false);
    tbc->tun_builder_exclude_route("::1", 128, -1, true);
    tbc->tun_builder_set_dns_options(dns_options);
    tbc->tun_builder_set_mtu(1500);
    tbc->tun_builder_set_session_name("onewaytickettothemoon");
    tbc->tun_builder_add_proxy_bypass("bypass.example.com");
    tbc->tun_builder_set_proxy_auto_config_url("http://wpad.yonan.net/");
    tbc->tun_builder_set_proxy_http("foo.bar.gov", 1234);
    tbc->tun_builder_set_proxy_https("zoo.bar.gov", 4321);
    tbc->tun_builder_add_wins_server("6.6.6.6");
    tbc->tun_builder_add_wins_server("7.7.7.7");
    tbc->tun_builder_set_allow_family(AF_INET6, true);

    // OPENVPN_LOG("TEXT #1:\n" << tbc->to_string());

    // const std::string fn1 = "cap1.txt";
    Json::Value j1 = tbc->to_json();
    const std::string j1_txt = j1.toStyledString();

    // OPENVPN_LOG("writing to " << fn1);

    /// write_string(fn1, j1_txt);
    // OPENVPN_LOG("JSON #1:\n" << j1_txt);

    // const std::string fn2 = "cap2.txt";
    TunBuilderCapture::Ptr tbc2 = TunBuilderCapture::from_json(j1);
    tbc2->validate();
    Json::Value j2 = tbc2->to_json();
    const std::string j2_txt = j2.toStyledString();
    // OPENVPN_LOG("writing to " << fn2);
    // write_string(fn2, j2_txt);
    // OPENVPN_LOG("JSON #2:\n" << j2_txt);

    ASSERT_EQ(j1_txt, j2_txt) << "round trip failed";
}

//  ===============================================================================================
//  RemoteAddress tests
//  ===============================================================================================

TEST(RemoteAddress, EmptyIsNotDefined)
{
    const TunBuilderCapture::RemoteAddress remote_address;
    ASSERT_FALSE(remote_address.defined());
}

RC_GTEST_PROP(RemoteAddress, NonEmptyIsDefined, ())
{
    const auto address = *rc::gen::nonEmpty<std::string>();
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.address = address;
    RC_ASSERT(remote_address.defined());
}

TEST(RemoteAddress, EmptyStringRepresentation)
{
    const TunBuilderCapture::RemoteAddress remote_address;
    ASSERT_TRUE(remote_address.to_string().empty());
}

TEST(RemoteAddress, EmptyStringRepresentationIncludesIPv6Setting)
{
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.ipv6 = true;
    ASSERT_EQ(remote_address.to_string(), " [IPv6]");
}

RC_GTEST_PROP(RemoteAddress, StringRepresentationReturnsAddress, (const std::string &address))
{
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.address = address;
    RC_ASSERT(remote_address.to_string() == address);
}

RC_GTEST_PROP(RemoteAddress, StringRepresentationIncludesIPv6Setting, (const std::string &address))
{
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.ipv6 = true;
    remote_address.address = address;
    RC_ASSERT(remote_address.to_string() == address + " [IPv6]");
}

RC_GTEST_PROP(RemoteAddress, EmptyThrowsOnValidation, (const std::string &title))
{
    const TunBuilderCapture::RemoteAddress remote_address;
    RC_ASSERT_THROWS_AS(remote_address.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(RemoteAddress, ValidatesIPv4, (const std::string &title))
{
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.address = *rc::IPv4Address().as("Valid IPv4 address");
    remote_address.validate(title);
}

RC_GTEST_PROP(RemoteAddress, ValidatesIPv6, (const std::string &title))
{
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.address = *rc::IPv6Address().as("Valid IPv6 address");
    // Assumption: you have to specify manually and don't forget to set .ipv6 or else it throws
    remote_address.ipv6 = true;
    remote_address.validate(title);
}

RC_GTEST_PROP(RemoteAddress, ThrowsValidatingMismatchedIPVersion, (const std::string &title, bool ipv6))
{
    TunBuilderCapture::RemoteAddress remote_address;
    // Intentionally generate IP Address with mismatched version: IPv4 if ipv6 is true, IPv6 otherwise
    remote_address.address = ipv6 ? *rc::IPv4Address().as("Valid IPv4 address") : *rc::IPv6Address().as("Valid IPv6 address");
    // Assumption: you have to specify manually
    remote_address.ipv6 = ipv6;
    RC_ASSERT_THROWS_AS(remote_address.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(RemoteAddress, ThrowsValidatingInvalidIP, (const std::string &title, bool ipv6))
{
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.address = ipv6 ? *rc::IPv6Address(false).as("Invalid IPv6 address") : *rc::IPv4Address(false).as("Invalid IPv4 address");
    // Assumption: you have to specify manually
    remote_address.ipv6 = ipv6;
    RC_ASSERT_THROWS_AS(remote_address.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(RemoteAddress, EmptyJsonRoundTripHaveSameStringRepresentation, (const std::string &title))
{
    const TunBuilderCapture::RemoteAddress remote_address;
    const auto address_as_json = remote_address.to_json();
    TunBuilderCapture::RemoteAddress from_json;
    from_json.from_json(address_as_json, title);
    RC_ASSERT(remote_address.to_string() == from_json.to_string());
}

RC_GTEST_PROP(RemoteAddress, EmptyJsonRoundTripHaveSameDefinedStatus, (const std::string &title))
{
    const TunBuilderCapture::RemoteAddress remote_address;
    const auto address_as_json = remote_address.to_json();
    TunBuilderCapture::RemoteAddress from_json;
    from_json.from_json(address_as_json, title);
    RC_ASSERT(remote_address.defined() == from_json.defined());
}

RC_GTEST_PROP(RemoteAddress, EmptyJsonRoundTripThrowsOnValidation, (const std::string &title))
{
    const TunBuilderCapture::RemoteAddress remote_address;
    RC_ASSERT_THROWS_AS(remote_address.validate(title), openvpn::IP::ip_exception);
    const auto address_as_json = remote_address.to_json();
    TunBuilderCapture::RemoteAddress from_json;
    from_json.from_json(address_as_json, title);
    RC_ASSERT_THROWS_AS(from_json.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(RemoteAddress, JsonRoundTripHaveSameStringRepresentation, (const std::string &address, const std::string &title, bool ipv6))
{
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.ipv6 = ipv6;
    remote_address.address = address;
    const auto address_as_json = remote_address.to_json();
    TunBuilderCapture::RemoteAddress from_json;
    from_json.from_json(address_as_json, title);
    RC_ASSERT(remote_address.to_string() == from_json.to_string());
}

RC_GTEST_PROP(RemoteAddress, JsonRoundTripHaveSameDefinedStatus, (const std::string &title))
{
    const TunBuilderCapture::RemoteAddress remote_address;
    const auto address_as_json = remote_address.to_json();
    TunBuilderCapture::RemoteAddress from_json;
    from_json.from_json(address_as_json, title);
    RC_ASSERT(remote_address.defined() == from_json.defined());
}

RC_GTEST_PROP(RemoteAddress, JsonRoundTripThrowsValidatingMismatchedIPVersion, (const std::string &title, bool ipv6))
{
    TunBuilderCapture::RemoteAddress remote_address;
    // Intentionally generate IP Address with mismatched version: IPv4 if ipv6 is true, IPv6 otherwise
    remote_address.address = ipv6 ? *rc::IPv4Address().as("Valid IPv4 address") : *rc::IPv6Address().as("Valid IPv6 address");
    remote_address.ipv6 = ipv6;
    RC_ASSERT_THROWS_AS(remote_address.validate(title), openvpn::IP::ip_exception);
    const auto address_as_json = remote_address.to_json();
    TunBuilderCapture::RemoteAddress from_json;
    from_json.from_json(address_as_json, title);
    RC_ASSERT_THROWS_AS(from_json.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(RemoteAddress, JsonRoundTripThrowsValidatingInvalidIP, (const std::string &title, bool ipv6))
{
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.address = ipv6 ? *rc::IPv6Address(false).as("Invalid IPv6 address") : *rc::IPv4Address(false).as("Invalid IPv4 address");
    remote_address.ipv6 = ipv6;
    RC_ASSERT_THROWS_AS(remote_address.validate(title), openvpn::IP::ip_exception);
    const auto address_as_json = remote_address.to_json();
    TunBuilderCapture::RemoteAddress from_json;
    from_json.from_json(address_as_json, title);
    RC_ASSERT_THROWS_AS(from_json.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(RemoteAddress, JsonRoundTripValidatesCorrectIP, (const std::string &title, bool ipv6))
{
    TunBuilderCapture::RemoteAddress remote_address;
    remote_address.address = ipv6 ? *rc::IPv6Address().as("Valid IPv6 address") : *rc::IPv4Address().as("Valid IPv4 address");
    remote_address.ipv6 = ipv6;
    remote_address.validate(title);
    const auto address_as_json = remote_address.to_json();
    TunBuilderCapture::RemoteAddress from_json;
    from_json.from_json(address_as_json, title);
    from_json.validate(title);
}

RC_GTEST_PROP(RemoteAddress, FromInvalidJsonDoesNotChangeOriginalObject, (const std::string &address, const std::string &title, bool ipv6))
{
    TunBuilderCapture::RemoteAddress from_json;
    from_json.ipv6 = ipv6;
    from_json.address = address;
    const Json::Value invalid_json;
    from_json.from_json(invalid_json, title);
    RC_ASSERT(from_json.ipv6 == ipv6);
    RC_ASSERT(from_json.address == address);
}

//  ===============================================================================================
//  RerouteGW tests
//  ===============================================================================================

TEST(RerouteGW, EmptyStringRepresentationReturnsUnsetOptions)
{
    constexpr TunBuilderCapture::RerouteGW reroute_gw;
    ASSERT_EQ(reroute_gw.to_string(), "IPv4=0 IPv6=0 flags=[ ]");
}

RC_GTEST_PROP(RerouteGW, StringRepresentationReturnsSetOptions, (bool ipv4, bool ipv6, rc::RedirectGatewayFlagsValues flags))
{
    TunBuilderCapture::RerouteGW reroute_gw;
    reroute_gw.ipv4 = ipv4;
    reroute_gw.ipv6 = ipv6;
    reroute_gw.flags = flags;
    // TODO: refactor original code so there's no need to rewrite method
    std::string ret;
    ret += "[ ";
    if (flags & RedirectGatewayFlags::RG_ENABLE)
        ret += "ENABLE ";
    if (flags & RedirectGatewayFlags::RG_REROUTE_GW)
        ret += "REROUTE_GW ";
    if (flags & RedirectGatewayFlags::RG_LOCAL)
        ret += "LOCAL ";
    if (flags & RedirectGatewayFlags::RG_AUTO_LOCAL)
        ret += "AUTO_LOCAL ";
    if (flags & RedirectGatewayFlags::RG_DEF1)
        ret += "DEF1 ";
    if (flags & RedirectGatewayFlags::RG_BYPASS_DHCP)
        ret += "BYPASS_DHCP ";
    if (flags & RedirectGatewayFlags::RG_BYPASS_DNS)
        ret += "BYPASS_DNS ";
    if (flags & RedirectGatewayFlags::RG_BLOCK_LOCAL)
        ret += "BLOCK_LOCAL ";
    if (flags & RedirectGatewayFlags::RG_IPv4)
        ret += "IPv4 ";
    if (flags & RedirectGatewayFlags::RG_IPv6)
        ret += "IPv6 ";
    ret += "]";
    const std::string ipv4_and_ipv6_return_string = {"IPv4=" + std::to_string(ipv4) + " IPv6=" + std::to_string(ipv6) + " "};
    RC_ASSERT(reroute_gw.to_string() == ipv4_and_ipv6_return_string + "flags=" + ret);
}

RC_GTEST_PROP(RerouteGW, EmptyJsonRoundTripHaveSameStringRepresentation, (const std::string &title))
{
    constexpr TunBuilderCapture::RerouteGW reroute_gw;
    const auto reroute_gw_as_json = reroute_gw.to_json();
    TunBuilderCapture::RerouteGW from_json;
    from_json.from_json(reroute_gw_as_json, title);
    RC_ASSERT(reroute_gw.to_string() == from_json.to_string());
}

RC_GTEST_PROP(RerouteGW, JsonRoundTripHaveSameStringRepresentation, (bool ipv4, bool ipv6, rc::RedirectGatewayFlagsValues flags, const std::string &title))
{
    TunBuilderCapture::RerouteGW reroute_gw;
    reroute_gw.ipv4 = ipv4;
    reroute_gw.ipv6 = ipv6;
    reroute_gw.flags = flags;
    const auto reroute_gw_as_json = reroute_gw.to_json();
    TunBuilderCapture::RerouteGW from_json;
    from_json.from_json(reroute_gw_as_json, title);
    RC_ASSERT(reroute_gw.to_string() == from_json.to_string());
}

RC_GTEST_PROP(RerouteGW, FromInvalidJsonThrows, (bool ipv4, bool ipv6, rc::RedirectGatewayFlagsValues flags, const std::string &title))
{
    TunBuilderCapture::RerouteGW from_json;
    from_json.ipv4 = ipv4;
    from_json.ipv6 = ipv6;
    from_json.flags = flags;
    const Json::Value invalid_json;
    RC_ASSERT_THROWS_AS(from_json.from_json(invalid_json, title), json::json_parse);
}

//  ===============================================================================================
//  RouteBased tests
//  ===============================================================================================

RC_GTEST_PROP(RouteBased, EmptyStringRepresentationReturnsUnsetPrefixLength, (rc::RouteBased route_based))
{
    std::visit(
        [](auto &&route_base_variant)
        { RC_ASSERT(route_base_variant.to_string() == "/0"); },
        route_based);
}

RC_GTEST_PROP(RouteBased, StringRepresentationReturnsSetOptions, (rc::RouteBased route_based, const std::string &address, unsigned char prefix_length, int metric, const std::string &gateway, bool ipv6, bool net30))
{
    std::visit(
        [&address, prefix_length, metric, &gateway, ipv6, net30](auto &&route_base_variant)
        {
            route_base_variant.address = address;
            route_base_variant.prefix_length = prefix_length;
            route_base_variant.metric = metric;
            route_base_variant.gateway = gateway;
            route_base_variant.ipv6 = ipv6;
            route_base_variant.net30 = net30;
            std::string output;
            output += address + "/" + std::to_string(prefix_length);
            if (!gateway.empty())
                output += " -> " + gateway;
            if (metric >= 0)
                output += " [METRIC=" + std::to_string(metric) + "]";
            if (ipv6)
                output += " [IPv6]";
            if (net30)
                output += " [net30]";
            RC_ASSERT(route_base_variant.to_string() == output);
        },
        route_based);
}


RC_GTEST_PROP(RouteBased, EmptyJsonRoundTripHaveSameStringRepresentation, (rc::RouteBased route_based, const std::string &title))
{
    std::visit(
        [&title](auto &&route_base_variant)
        {
            const auto route_based_as_json = route_base_variant.to_json();
            using T = std::decay_t<decltype(route_base_variant)>;
            T from_json;
            from_json.from_json(route_based_as_json, title);
            RC_ASSERT(route_base_variant.to_string() == from_json.to_string());
        },
        route_based);
}

RC_GTEST_PROP(RouteBased, JsonRoundTripHaveSameStringRepresentation, (rc::RouteBased route_based, const std::string &address, unsigned char prefix_length, int metric, const std::string &gateway, bool ipv6, bool net30, const std::string &title))
{
    std::visit(
        [&address, prefix_length, metric, &gateway, ipv6, net30, &title](auto &&route_base_variant)
        {
            route_base_variant.address = address;
            route_base_variant.prefix_length = prefix_length;
            route_base_variant.metric = metric;
            route_base_variant.gateway = gateway;
            route_base_variant.ipv6 = ipv6;
            route_base_variant.net30 = net30;
            const auto route_based_as_json = route_base_variant.to_json();
            using T = std::decay_t<decltype(route_base_variant)>;
            T from_json;
            from_json.from_json(route_based_as_json, title);
            RC_ASSERT(route_base_variant.to_string() == from_json.to_string());
        },
        route_based);
}

//  ===============================================================================================
//  ProxyBypass tests
//  ===============================================================================================

TEST(ProxyBypass, EmptyIsNotDefined)
{
    const TunBuilderCapture::ProxyBypass proxy_bypass;
    ASSERT_FALSE(proxy_bypass.defined());
}

RC_GTEST_PROP(ProxyBypass, NonEmptyIsDefined, ())
{
    const auto bypass_host = *rc::gen::nonEmpty<std::string>();
    TunBuilderCapture::ProxyBypass proxy_bypass;
    proxy_bypass.bypass_host = bypass_host;
    RC_ASSERT(proxy_bypass.defined());
}

TEST(ProxyBypass, EmptyStringRepresentation)
{
    const TunBuilderCapture::ProxyBypass proxy_bypass;
    ASSERT_TRUE(proxy_bypass.to_string().empty());
}

RC_GTEST_PROP(ProxyBypass, StringRepresentationReturnBypassHost, (const std::string &bypass_host))
{
    TunBuilderCapture::ProxyBypass proxy_bypass;
    proxy_bypass.bypass_host = bypass_host;
    RC_ASSERT(proxy_bypass.to_string() == bypass_host);
}

RC_GTEST_PROP(ProxyBypass, EmptyValidates, (const std::string &title))
{
    const TunBuilderCapture::ProxyBypass proxy_bypass;
    proxy_bypass.validate(title);
}

RC_GTEST_PROP(ProxyBypass, EmptyJsonRoundTripHaveSameStringRepresentation, (const std::string &title))
{
    const TunBuilderCapture::ProxyBypass proxy_bypass;
    const auto proxy_bypass_as_json = proxy_bypass.to_json();
    TunBuilderCapture::ProxyBypass from_json;
    from_json.from_json(proxy_bypass_as_json, title);
    RC_ASSERT(proxy_bypass.to_string() == from_json.to_string());
}

RC_GTEST_PROP(ProxyBypass, EmptyJsonRoundTripHaveSameDefinedStatus, (const std::string &title))
{
    const TunBuilderCapture::ProxyBypass proxy_bypass;
    const auto proxy_bypass_as_json = proxy_bypass.to_json();
    TunBuilderCapture::ProxyBypass from_json;
    from_json.from_json(proxy_bypass_as_json, title);
    RC_ASSERT(proxy_bypass.defined() == from_json.defined());
}

RC_GTEST_PROP(ProxyBypass, EmptyJsonRoundTripValidates, (const std::string &title))
{
    const TunBuilderCapture::ProxyBypass proxy_bypass;
    proxy_bypass.validate(title);
    const auto proxy_bypass_as_json = proxy_bypass.to_json();
    TunBuilderCapture::ProxyBypass from_json;
    from_json.from_json(proxy_bypass_as_json, title);
    from_json.validate(title);
}

RC_GTEST_PROP(ProxyBypass, JsonRoundTripHaveSameStringRepresentation, (const std::string &bypass_host, const std::string &title))
{
    TunBuilderCapture::ProxyBypass proxy_bypass;
    proxy_bypass.bypass_host = bypass_host;
    const auto proxy_bypass_as_json = proxy_bypass.to_json();
    TunBuilderCapture::ProxyBypass from_json;
    from_json.from_json(proxy_bypass_as_json, title);
    RC_ASSERT(proxy_bypass.to_string() == from_json.to_string());
}

RC_GTEST_PROP(ProxyBypass, JsonRoundTripHaveSameDefinedStatus, (const std::string &bypass_host, const std::string &title))
{
    TunBuilderCapture::ProxyBypass proxy_bypass;
    proxy_bypass.bypass_host = bypass_host;
    const auto proxy_bypass_as_json = proxy_bypass.to_json();
    TunBuilderCapture::ProxyBypass from_json;
    from_json.from_json(proxy_bypass_as_json, title);
    RC_ASSERT(proxy_bypass.defined() == from_json.defined());
}

RC_GTEST_PROP(ProxyBypass, FromInvalidJsonThrows, (const std::string &title))
{
    TunBuilderCapture::ProxyBypass from_json;
    const Json::Value invalid_json;
    RC_ASSERT_THROWS_AS(from_json.from_json(invalid_json, title), json::json_parse);
}

//  ===============================================================================================
//  ProxyAutoConfigURL tests
//  ===============================================================================================

TEST(ProxyAutoConfigURL, EmptyIsNotDefined)
{
    const TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    ASSERT_FALSE(proxy_autoconfig_url.defined());
}

RC_GTEST_PROP(ProxyAutoConfigURL, NonEmptyIsDefined, ())
{
    const auto url = *rc::gen::nonEmpty<std::string>();
    TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    proxy_autoconfig_url.url = url;
    RC_ASSERT(proxy_autoconfig_url.defined());
}

TEST(ProxyAutoConfigURL, EmptyStringRepresentation)
{
    const TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    ASSERT_TRUE(proxy_autoconfig_url.to_string().empty());
}

RC_GTEST_PROP(ProxyAutoConfigURL, StringRepresentationReturnsURL, (const std::string &url))
{
    TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    proxy_autoconfig_url.url = url;
    RC_ASSERT(proxy_autoconfig_url.to_string() == url);
}

RC_GTEST_PROP(ProxyAutoConfigURL, EmptyValidates, (const std::string &title))
{
    const TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    proxy_autoconfig_url.validate(title);
}

RC_GTEST_PROP(ProxyAutoConfigURL, EmptyJsonRoundTripHaveSameStringRepresentation, (const std::string &title))
{
    const TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    const auto proxy_autoconfig_url_as_json = proxy_autoconfig_url.to_json();
    TunBuilderCapture::ProxyAutoConfigURL from_json;
    from_json.from_json(proxy_autoconfig_url_as_json, title);
    RC_ASSERT(proxy_autoconfig_url.to_string() == from_json.to_string());
}

RC_GTEST_PROP(ProxyAutoConfigURL, EmptyJsonRoundTripHaveSameDefinedStatus, (const std::string &title))
{
    const TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    const auto proxy_autoconfig_url_as_json = proxy_autoconfig_url.to_json();
    TunBuilderCapture::ProxyAutoConfigURL from_json;
    from_json.from_json(proxy_autoconfig_url_as_json, title);
    RC_ASSERT(proxy_autoconfig_url.defined() == from_json.defined());
}

RC_GTEST_PROP(ProxyAutoConfigURL, EmptyJsonRoundTripValidates, (const std::string &title))
{
    const TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    proxy_autoconfig_url.validate(title);
    const auto proxy_autoconfig_url_as_json = proxy_autoconfig_url.to_json();
    TunBuilderCapture::ProxyAutoConfigURL from_json;
    from_json.from_json(proxy_autoconfig_url_as_json, title);
    from_json.validate(title);
}

RC_GTEST_PROP(ProxyAutoConfigURL, JsonRoundTripHaveSameStringRepresentation, (const std::string &url, const std::string &title))
{
    TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    proxy_autoconfig_url.url = url;
    const auto proxy_autoconfig_url_as_json = proxy_autoconfig_url.to_json();
    TunBuilderCapture::ProxyAutoConfigURL from_json;
    from_json.from_json(proxy_autoconfig_url_as_json, title);
    RC_ASSERT(proxy_autoconfig_url.to_string() == from_json.to_string());
}

RC_GTEST_PROP(ProxyAutoConfigURL, JsonRoundTripHaveSameDefinedStatus, (const std::string &url, const std::string &title))
{
    TunBuilderCapture::ProxyAutoConfigURL proxy_autoconfig_url;
    proxy_autoconfig_url.url = url;
    const auto proxy_autoconfig_url_as_json = proxy_autoconfig_url.to_json();
    TunBuilderCapture::ProxyAutoConfigURL from_json;
    from_json.from_json(proxy_autoconfig_url_as_json, title);
    RC_ASSERT(proxy_autoconfig_url.defined() == from_json.defined());
}

RC_GTEST_PROP(ProxyAutoConfigURL, FromInvalidJsonDoesNotChangeOriginalObject, (const std::string &domain, const std::string &title))
{
    TunBuilderCapture::ProxyAutoConfigURL from_json;
    from_json.url = domain;
    const Json::Value invalid_json;
    from_json.from_json(invalid_json, title);
    RC_ASSERT(from_json.url == domain);
}

//  ===============================================================================================
//  ProxyHostPort tests
//  ===============================================================================================

TEST(ProxyHostPort, EmptyIsNotDefined)
{
    const TunBuilderCapture::ProxyHostPort proxy_host_port;
    ASSERT_FALSE(proxy_host_port.defined());
}

RC_GTEST_PROP(ProxyHostPort, NonEmptyIsDefined, ())
{
    const auto host = *rc::gen::nonEmpty<std::string>();
    TunBuilderCapture::ProxyHostPort proxy_host_port;
    proxy_host_port.host = host;
    RC_ASSERT(proxy_host_port.defined());
}

TEST(ProxyHostPort, EmptyStringRepresentationReturnsDefaultPort)
{
    const TunBuilderCapture::ProxyHostPort proxy_host_port;
    ASSERT_EQ(proxy_host_port.to_string(), std::string{" "} + std::to_string(proxy_host_port.port));
}

RC_GTEST_PROP(ProxyHostPort, StringRepresentationReturnsHostPort, (const std::string &host, const int port))
{
    TunBuilderCapture::ProxyHostPort proxy_host_port;
    proxy_host_port.host = host;
    proxy_host_port.port = port;
    RC_ASSERT(proxy_host_port.to_string() == host + std::string{" "} + std::to_string(port));
}

RC_GTEST_PROP(ProxyHostPort, EmptyValidates, (const std::string &title))
{
    const TunBuilderCapture::ProxyHostPort proxy_host_port;
    proxy_host_port.validate(title);
}

RC_GTEST_PROP(ProxyHostPort, EmptyJsonRoundTripHaveSameStringRepresentation, (const std::string &title))
{
    const TunBuilderCapture::ProxyHostPort proxy_host_port;
    const auto proxy_host_port_as_json = proxy_host_port.to_json();
    TunBuilderCapture::ProxyHostPort from_json;
    from_json.from_json(proxy_host_port_as_json, title);
    RC_ASSERT(proxy_host_port.to_string() == from_json.to_string());
}

RC_GTEST_PROP(ProxyHostPort, EmptyJsonRoundTripHaveSameDefinedStatus, (const std::string &title))
{
    const TunBuilderCapture::ProxyHostPort proxy_host_port;
    const auto proxy_host_port_as_json = proxy_host_port.to_json();
    TunBuilderCapture::ProxyHostPort from_json;
    from_json.from_json(proxy_host_port_as_json, title);
    RC_ASSERT(proxy_host_port.defined() == from_json.defined());
}

RC_GTEST_PROP(ProxyHostPort, EmptyJsonRoundTripValidates, (const std::string &title))
{
    const TunBuilderCapture::ProxyHostPort proxy_host_port;
    proxy_host_port.validate(title);
    const auto proxy_host_port_as_json = proxy_host_port.to_json();
    TunBuilderCapture::ProxyHostPort from_json;
    from_json.from_json(proxy_host_port_as_json, title);
    from_json.validate(title);
}

RC_GTEST_PROP(ProxyHostPort, JsonRoundTripHaveSameStringRepresentation, (const std::string &host, const int port, const std::string &title))
{
    TunBuilderCapture::ProxyHostPort proxy_host_port;
    proxy_host_port.host = host;
    proxy_host_port.port = port;
    const auto proxy_host_port_as_json = proxy_host_port.to_json();
    TunBuilderCapture::ProxyHostPort from_json;
    from_json.from_json(proxy_host_port_as_json, title);
    RC_ASSERT(proxy_host_port.to_string() == from_json.to_string());
}

RC_GTEST_PROP(ProxyHostPort, JsonRoundTripHaveSameDefinedStatus, (const std::string &host, const std::string &title))
{
    TunBuilderCapture::ProxyHostPort proxy_host_port;
    proxy_host_port.host = host;
    const auto proxy_host_port_as_json = proxy_host_port.to_json();
    TunBuilderCapture::ProxyHostPort from_json;
    from_json.from_json(proxy_host_port_as_json, title);
    RC_ASSERT(proxy_host_port.defined() == from_json.defined());
}

RC_GTEST_PROP(ProxyHostPort, FromInvalidJsonDoesNotChangeOriginalObject, (const std::string &host, const int port, const std::string &title))
{
    TunBuilderCapture::ProxyHostPort from_json;
    from_json.host = host;
    from_json.port = port;
    const Json::Value invalid_json;
    from_json.from_json(invalid_json, title);
    RC_ASSERT(from_json.host == host);
    RC_ASSERT(from_json.port == port);
}

//  ===============================================================================================
//  WINSServer tests
//  ===============================================================================================

TEST(WINSServer, EmptyStringRepresentation)
{
    const TunBuilderCapture::WINSServer wins_server;
    ASSERT_TRUE(wins_server.to_string().empty());
}

RC_GTEST_PROP(WINSServer, StringRepresentationReturnsAddress, (const std::string &address))
{
    TunBuilderCapture::WINSServer wins_server;
    wins_server.address = address;
    RC_ASSERT(wins_server.to_string() == address);
}

RC_GTEST_PROP(WINSServer, EmptyThrowsOnValidation, (const std::string &title))
{
    const TunBuilderCapture::WINSServer wins_server;
    RC_ASSERT_THROWS_AS(wins_server.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(WINSServer, ValidatesAddress, (const std::string &title))
{
    TunBuilderCapture::WINSServer wins_server;
    wins_server.address = *rc::IPv4Address().as("Valid IPv4 address");
    wins_server.validate(title);
}

RC_GTEST_PROP(WINSServer, ThrowsValidatingInvalidAddress, (const std::string &title))
{
    TunBuilderCapture::WINSServer wins_server;
    wins_server.address = *rc::IPv4Address(false).as("Invalid IPv4 address");
    RC_ASSERT_THROWS_AS(wins_server.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(WINSServer, EmptyJsonRoundTripHaveSameStringRepresentation, (const std::string &title))
{
    const TunBuilderCapture::WINSServer wins_server;
    const auto wins_server_as_json = wins_server.to_json();
    TunBuilderCapture::WINSServer from_json;
    from_json.from_json(wins_server_as_json, title);
    RC_ASSERT(wins_server.to_string() == from_json.to_string());
}

RC_GTEST_PROP(WINSServer, EmptyJsonRoundTripThrowsOnValidation, (const std::string &title))
{
    const TunBuilderCapture::WINSServer wins_server;
    RC_ASSERT_THROWS_AS(wins_server.validate(title), openvpn::IP::ip_exception);
    const auto wins_server_as_json = wins_server.to_json();
    TunBuilderCapture::WINSServer from_json;
    from_json.from_json(wins_server_as_json, title);
    RC_ASSERT_THROWS_AS(from_json.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(WINSServer, JsonRoundTripHaveSameStringRepresentation, (const std::string &address, const std::string &title))
{
    TunBuilderCapture::WINSServer wins_server;
    wins_server.address = address;
    const auto wins_server_as_json = wins_server.to_json();
    TunBuilderCapture::WINSServer from_json;
    from_json.from_json(wins_server_as_json, title);
    RC_ASSERT(wins_server.to_string() == from_json.to_string());
}

RC_GTEST_PROP(WINSServer, JsonRoundTripValidatesAddress, (const std::string &title))
{
    TunBuilderCapture::WINSServer wins_server;
    wins_server.address = *rc::IPv4Address().as("Valid IPv4 address");
    wins_server.validate(title);
    const auto wins_server_as_json = wins_server.to_json();
    TunBuilderCapture::WINSServer from_json;
    from_json.from_json(wins_server_as_json, title);
    from_json.validate(title);
}

RC_GTEST_PROP(WINSServer, JsonRoundTripThrowsValidatingInvalidIP, (const std::string &title))
{
    TunBuilderCapture::WINSServer wins_server;
    wins_server.address = *rc::IPv4Address(false).as("Invalid IPv4 address");
    RC_ASSERT_THROWS_AS(wins_server.validate(title), openvpn::IP::ip_exception);
    const auto wins_server_as_json = wins_server.to_json();
    TunBuilderCapture::WINSServer from_json;
    from_json.from_json(wins_server_as_json, title);
    RC_ASSERT_THROWS_AS(from_json.validate(title), openvpn::IP::ip_exception);
}

RC_GTEST_PROP(WINSServer, FromInvalidJsonThrows, (const std::string &title))
{
    TunBuilderCapture::WINSServer from_json;
    const Json::Value invalid_json;
    RC_ASSERT_THROWS_AS(from_json.from_json(invalid_json, title), json::json_parse);
}
