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


#include "test_common.hpp"

#include <json/value.h>
#include <openvpn/client/dns.hpp>

using namespace openvpn;

namespace unittests {

TEST(Dns, Options)
{
    OptionList config;

    config.parse_from_config(
        "dns server 1 address 1.1.1.1\n"
        "dns search-domains domain0 domain1\n"
        "dns server -2 address [2.2.2.2]:5353\n"
        "dns server -2 resolve-domains rdom0\n"
        "dns server 1 address [1::1]:5353\n"
        "dns search-domains domain2\n"
        "dns server -2 resolve-domains rdom1\n"
        "dns server -2 dnssec optional\n"
        "dns server -2 transport DoT\n"
        "dns server -2 sni hostname\n"
        "dns server 3 address 3::3 3.2.1.0:4242 [3:3::3:3]:3333\n"
        "dns server 3 dnssec no\n"
        "dns server 3 transport DoH\n",
        nullptr);
    config.update_map();

    DnsOptionsParser dns(config, false);

    ASSERT_EQ(dns.search_domains.size(), 3U);
    ASSERT_EQ(dns.search_domains[0].to_string(), "domain0");
    ASSERT_EQ(dns.search_domains[1].to_string(), "domain1");
    ASSERT_EQ(dns.search_domains[2].to_string(), "domain2");

    ASSERT_EQ(dns.servers.size(), 3U);

    int i = 1;
    for (const auto &keyval : dns.servers)
    {
        auto priority = keyval.first;
        auto &server = keyval.second;

        if (priority == -2)
        {
            ASSERT_EQ(i, 1);

            ASSERT_TRUE(server.addresses.size() == 1U);
            ASSERT_EQ(server.addresses[0].address, "2.2.2.2");
            ASSERT_EQ(server.addresses[0].port, 5353U);

            ASSERT_EQ(server.domains.size(), 2U);
            ASSERT_EQ(server.domains[0].to_string(), "rdom0");
            ASSERT_EQ(server.domains[1].to_string(), "rdom1");

            ASSERT_EQ(server.dnssec, DnsServer::Security::Optional);

            ASSERT_EQ(server.transport, DnsServer::Transport::TLS);
            ASSERT_EQ(server.sni, "hostname");
        }
        else if (priority == 1)
        {
            ASSERT_EQ(i, 2);

            ASSERT_TRUE(server.addresses.size() == 2U);
            ASSERT_EQ(server.addresses[0].address, "1.1.1.1");
            ASSERT_EQ(server.addresses[0].port, 0U);

            ASSERT_EQ(server.addresses[1].address, "1::1");
            ASSERT_EQ(server.addresses[1].port, 5353U);

            ASSERT_EQ(server.domains.size(), 0U);

            ASSERT_EQ(server.dnssec, DnsServer::Security::Unset);

            ASSERT_EQ(server.transport, DnsServer::Transport::Unset);
            ASSERT_TRUE(server.sni.empty());
        }
        else if (priority == 3)
        {
            ASSERT_EQ(i, 3);

            ASSERT_TRUE(server.addresses.size() == 3U);
            ASSERT_EQ(server.addresses[0].address, "3::3");
            ASSERT_EQ(server.addresses[0].port, 0U);

            ASSERT_EQ(server.addresses[1].address, "3.2.1.0");
            ASSERT_EQ(server.addresses[1].port, 4242U);

            ASSERT_EQ(server.addresses[2].address, "3:3::3:3");
            ASSERT_EQ(server.addresses[2].port, 3333U);

            ASSERT_EQ(server.domains.size(), 0U);

            ASSERT_EQ(server.dnssec, DnsServer::Security::No);

            ASSERT_EQ(server.transport, DnsServer::Transport::HTTPS);
            ASSERT_TRUE(server.sni.empty());
        }

        i++;
    }
}

TEST(Dns, OptionsMerger)
{
    OptionList pushed;
    OptionList config;
    DnsOptionsMerger merger;

    pushed.parse_from_config("dns server 1 address ::1", nullptr);
    config.parse_from_config("dns server 1 address 1.1.1.1\n"
                             "dns server -2 address 2.2.2.2\n",
                             nullptr);
    pushed.update_map();
    config.update_map();

    merger.merge(pushed, config);
    ASSERT_EQ(config.size(), 2U);
    ASSERT_EQ(pushed.size(), 2U);
    ASSERT_EQ(pushed[0].ref(4), "::1");
    ASSERT_EQ(pushed[1].ref(4), "2.2.2.2");
}

TEST(Dns, DnsAddressTostring)
{
    /**
     * Supported formats:
     *   192.168.0.1
     *   192.168.0.1:53
     *   [2001:db8:1234::1]
     *   [2001:db8:1234::1]:53
     */

    DnsAddress ipv4_addr("192.168.0.1");
    EXPECT_STREQ(ipv4_addr.to_string().c_str(), "192.168.0.1");
    DnsAddress parse_ipv4_addr(ipv4_addr.to_string());
    EXPECT_STREQ(parse_ipv4_addr.to_string().c_str(), "192.168.0.1");

    DnsAddress ipv4_port("192.168.20.1:9876");
    EXPECT_STREQ(ipv4_port.to_string().c_str(), "192.168.20.1:9876");
    DnsAddress parse_ipv4_port(ipv4_port.to_string());
    EXPECT_STREQ(parse_ipv4_port.to_string().c_str(), "192.168.20.1:9876");

    DnsAddress ipv6_addr("2001:db8:5678::1");
    EXPECT_STREQ(ipv6_addr.to_string().c_str(), "2001:db8:5678::1");
    DnsAddress parse_ipv6_addr(ipv6_addr.to_string());
    EXPECT_STREQ(parse_ipv6_addr.to_string().c_str(), "2001:db8:5678::1")
        << "parse_ipv6_addr failed";

    DnsAddress ipv6_port("[2001:db8:1234::1]:5678");
    EXPECT_STREQ(ipv6_port.to_string().c_str(), "[2001:db8:1234::1]:5678");
    DnsAddress parse_ipv6_port(ipv6_port.to_string());
    EXPECT_STREQ(parse_ipv6_port.to_string().c_str(), "[2001:db8:1234::1]:5678")
        << "parse_ipv6_port failed";


#ifndef OPENVPN_PLATFORM_WIN
    // Test disabled on Windows.  Windows allows partial IP address strings.
    // On Linux, this error happens inside the ASIO library when calling
    // inet_pton() in asio::ip::make_address_v4()
    OVPN_EXPECT_THROW(DnsAddress invalid1("192.168.0"),
                      openvpn::Exception,
                      "Invalid address '192.168.0'");
#endif

    OVPN_EXPECT_THROW(DnsAddress invalid2("192.168.200.1::1234"),
                      openvpn::Exception,
                      "Invalid address '192.168.200.1::1234'");

    OVPN_EXPECT_THROW(DnsAddress invalid3("192.168.200.1:blabla"),
                      openvpn::Exception,
                      "Invalid address:port format '192.168.200.1:blabla'");

    OVPN_EXPECT_THROW(DnsAddress invalid4("192.168.200.1:77701"),
                      openvpn::Exception,
                      "Invalid address:port format '192.168.200.1:77701'");

    OVPN_EXPECT_THROW(DnsAddress invalid5("2001:defg:1234:1234::"),
                      openvpn::Exception,
                      "Invalid address '2001:defg:1234:1234::'");

    OVPN_EXPECT_THROW(DnsAddress invalid6("2001:abcd:1234:12345::1"),
                      openvpn::Exception,
                      "Invalid address '2001:abcd:1234:12345::1'");

    OVPN_EXPECT_THROW(DnsAddress invalid7("[2001:abcd:1234:::]"),
                      openvpn::Exception,
                      "Invalid address '2001:abcd:1234:::'");

    OVPN_EXPECT_THROW(DnsAddress invalid8("[2001:abcd:1234::]:65547"),
                      openvpn::Exception,
                      "Invalid address:port format '[2001:abcd:1234::]:65547");
}


TEST(Dns, ServerNoAddress)
{
    OptionList config;
    config.parse_from_config("dns server 0 resolve-domains dom0\n", nullptr);
    config.update_map();
    JY_EXPECT_THROW(DnsOptionsParser dns(config, false),
                    option_error,
                    "dns server 0 does not have an address assigned");
}

TEST(Dns, ServerEightAddresses)
{
    OptionList config;
    config.parse_from_config("dns server 0 address 1::1 2::2 3::3 4::4 5::5 6::6 7::7 8::8\n", nullptr);
    config.update_map();
    DnsOptionsParser dns(config, false);
    ASSERT_EQ(dns.servers.size(), 1U);
    ASSERT_EQ(dns.servers[0].addresses.size(), 8U);
}

TEST(Dns, ServerTooManyAddresses)
{
    OptionList config;
    config.parse_from_config("dns server 0 address 1::1 2::2 3::3 4::4 5::5 6::6 7::7 8::8 9::9\n", nullptr);
    config.update_map();
    JY_EXPECT_THROW(DnsOptionsParser dns(config, false),
                    option_error,
                    "dns server 0 option 'address' unknown or too many parameters");
}

TEST(Dns, ServerInvalidAddress)
{
    OptionList config;
    config.parse_from_config("dns server 0 address 1.1.1.1 foobar\n", nullptr);
    config.update_map();
    OVPN_EXPECT_THROW(DnsOptionsParser dns(config, false),
                      option_error,
                      "dns server 0 error: Invalid address 'foobar'");
}

TEST(Dns, ServerInvalidDnssec)
{
    {
        OptionList config;
        config.parse_from_config("dns server 0 dnssec foo\n", nullptr);
        config.update_map();
        OVPN_EXPECT_THROW(DnsOptionsParser dns(config, false),
                          option_error,
                          "dns server 0 error: Invalid DNSSEC value 'foo'");
    }
    {
        OptionList config;
        config.parse_from_config("dns server 0 dnssec yes no\n", nullptr);
        config.update_map();
        JY_EXPECT_THROW(DnsOptionsParser dns(config, false),
                        option_error,
                        "dns server 0 option 'dnssec' unknown or too many parameters");
    }
}

TEST(Dns, ServerInvalidTransport)
{
    {
        OptionList config;
        config.parse_from_config("dns server 0 transport avian-carrier\n", nullptr);
        config.update_map();
        OVPN_EXPECT_THROW(DnsOptionsParser dns(config, false),
                          option_error,
                          "dns server 0 error: Invalid transport value 'avian-carrier'");
    }
    {
        OptionList config;
        config.parse_from_config("dns server 0 transport DoT D'oh\n", nullptr);
        config.update_map();
        JY_EXPECT_THROW(DnsOptionsParser dns(config, false),
                        option_error,
                        "dns server 0 option 'transport' unknown or too many parameters");
    }
}

TEST(Dns, DhcpOptions)
{
    OptionList config;
    config.parse_from_config(
        "dhcp-option DNS 1.1.1.1\n"
        "dhcp-option DNS6 1::1\n"
        "dhcp-option DOMAIN domain0\n"
        "dhcp-option DOMAIN-SEARCH domain1\n"
        "dhcp-option ADAPTER_DOMAIN_SUFFIX adsX\n"
        "dhcp-option ADAPTER_DOMAIN_SUFFIX ads\n",
        nullptr);
    config.update_map();

    DnsOptionsParser dns(config, false);

    ASSERT_TRUE(dns.from_dhcp_options);

    ASSERT_EQ(dns.search_domains.size(), 3U);
    ASSERT_EQ(dns.search_domains[0].to_string(), "ads");
    ASSERT_EQ(dns.search_domains[1].to_string(), "domain0");
    ASSERT_EQ(dns.search_domains[2].to_string(), "domain1");

    ASSERT_EQ(dns.servers.size(), 1U);
    ASSERT_TRUE(dns.servers[0].addresses.size() == 2U);
    ASSERT_EQ(dns.servers[0].addresses[0].address, "1.1.1.1");
    ASSERT_EQ(dns.servers[0].addresses[0].port, 0U);

    ASSERT_EQ(dns.servers[0].addresses[1].address, "1::1");
    ASSERT_EQ(dns.servers[0].addresses[1].port, 0U);
}

TEST(Dns, DhcpOptionsWithSplitDomains)
{
    OptionList config;
    config.parse_from_config(
        "dhcp-option DNS 1.1.1.1\n"
        "dhcp-option DNS6 1::1\n"
        "dhcp-option DOMAIN domain0\n"
        "dhcp-option DOMAIN-SEARCH domain1\n"
        "dhcp-option ADAPTER_DOMAIN_SUFFIX adsX\n"
        "dhcp-option ADAPTER_DOMAIN_SUFFIX ads\n",
        nullptr);
    config.update_map();

    DnsOptionsParser dns(config, true);

    ASSERT_TRUE(dns.from_dhcp_options);

    ASSERT_EQ(dns.search_domains.size(), 1U);
    ASSERT_EQ(dns.search_domains[0].to_string(), "ads");

    ASSERT_EQ(dns.servers.size(), 1U);

    ASSERT_TRUE(dns.servers[0].addresses.size() == 2U);
    ASSERT_EQ(dns.servers[0].addresses[0].address, "1.1.1.1");
    ASSERT_EQ(dns.servers[0].addresses[0].port, 0U);
    ASSERT_EQ(dns.servers[0].addresses[1].address, "1::1");
    ASSERT_EQ(dns.servers[0].addresses[1].port, 0U);

    ASSERT_TRUE(dns.servers[0].domains.size() == 2U);
    ASSERT_EQ(dns.servers[0].domains[0].domain, "domain0");
    ASSERT_EQ(dns.servers[0].domains[1].domain, "domain1");
}

TEST(Dns, DhcpOptionsIgnored)
{
    OptionList config;
    config.parse_from_config(
        "dhcp-option DNS 1.1.1.1\n"
        "dhcp-option DNS6 1::1\n"
        "dhcp-option DOMAIN domain0\n"
        "dhcp-option DOMAIN-SEARCH domain1\n"
        "dhcp-option ADAPTER_DOMAIN_SUFFIX adsX\n"
        "dns server 123 address 123::123\n"
        "dhcp-option ADAPTER_DOMAIN_SUFFIX ads\n",
        nullptr);
    config.update_map();

    DnsOptionsParser dns(config, true);

    ASSERT_FALSE(dns.from_dhcp_options);
    ASSERT_TRUE(dns.search_domains.empty());
    ASSERT_EQ(dns.servers.size(), 1U);

    ASSERT_TRUE(dns.servers[123].domains.empty());
    ASSERT_TRUE(dns.servers[123].addresses.size() == 1U);
    ASSERT_EQ(dns.servers[123].addresses[0].address, "123::123");
    ASSERT_EQ(dns.servers[123].addresses[0].port, 0U);
}

TEST(Dns, ToStringMinValuesSet)
{
    OptionList config;
    config.parse_from_config("dns server 10 address 1::1\n", nullptr);
    config.update_map();
    DnsOptionsParser dns(config, false);
    ASSERT_EQ(dns.to_string(),
              "DNS Servers:\n"
              "  Priority: 10\n"
              "  Addresses:\n"
              "    1::1\n"
              "Values from dhcp-options: false\n");
}

TEST(Dns, ToStringValuesFromDhcpOptions)
{
    OptionList config;
    config.parse_from_config("dhcp-option DNS6 1::1\n", nullptr);
    config.update_map();
    DnsOptionsParser dns(config, false);
    ASSERT_EQ(dns.to_string(),
              "DNS Servers:\n"
              "  Priority: 0\n"
              "  Addresses:\n"
              "    1::1\n"
              "Values from dhcp-options: true\n");
}

TEST(Dns, ToStringAllValuesSet)
{
    OptionList config;
    config.parse_from_config(
        "dns search-domains dom1 dom2 dom3\n"
        "dns server 10 address 1::1 1.1.1.1\n"
        "dns server 10 resolve-domains rdom11 rdom12\n"
        "dns server 10 transport DoT\n"
        "dns server 10 sni snidom1\n"
        "dns server 10 dnssec optional\n"
        "dns server 20 address 2::2 2.2.2.2\n"
        "dns server 20 resolve-domains rdom21 rdom22\n"
        "dns server 20 transport DoH\n"
        "dns server 20 sni snidom2\n"
        "dns server 20 dnssec yes\n",
        nullptr);
    config.update_map();
    DnsOptionsParser dns(config, false);
    ASSERT_EQ(dns.to_string(),
              "DNS Servers:\n"
              "  Priority: 10\n"
              "  Addresses:\n"
              "    1::1\n"
              "    1.1.1.1\n"
              "  Domains:\n"
              "    rdom11\n"
              "    rdom12\n"
              "  DNSSEC: Optional\n"
              "  Transport: TLS\n"
              "  SNI: snidom1\n"
              "  Priority: 20\n"
              "  Addresses:\n"
              "    2::2\n"
              "    2.2.2.2\n"
              "  Domains:\n"
              "    rdom21\n"
              "    rdom22\n"
              "  DNSSEC: Yes\n"
              "  Transport: HTTPS\n"
              "  SNI: snidom2\n"
              "DNS Search Domains:\n"
              "  dom1\n"
              "  dom2\n"
              "  dom3\n"
              "Values from dhcp-options: false\n");
}

TEST(Dns, JsonRoundtripMinValuesSet)
{
    OptionList config;
    config.parse_from_config("dns server 10 address 1::1\n", nullptr);
    config.update_map();
    DnsOptionsParser toJson(config, false);
    Json::Value json = toJson.to_json();
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    ASSERT_EQ(Json::writeString(builder, json),
              "{\n"
              "  \"from_dhcp_options\" : false,\n"
              "  \"servers\" : \n"
              "  {\n"
              "    \"10\" : \n"
              "    {\n"
              "      \"addresses\" : \n"
              "      [\n"
              "        {\n"
              "          \"address\" : \"1::1\"\n"
              "        }\n"
              "      ]\n"
              "    }\n"
              "  }\n"
              "}");

    DnsOptions fromJson;
    fromJson.from_json(json, "json test");
    ASSERT_EQ(fromJson.to_string(),
              "DNS Servers:\n"
              "  Priority: 10\n"
              "  Addresses:\n"
              "    1::1\n"
              "Values from dhcp-options: false\n");
}

TEST(Dns, JsonRoundtripValuesFromDhcpOption)
{
    OptionList config;
    config.parse_from_config("dhcp-option DNS6 1::1\n", nullptr);
    config.update_map();
    DnsOptionsParser toJson(config, false);
    Json::Value json = toJson.to_json();
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    ASSERT_EQ(Json::writeString(builder, json),
              "{\n"
              "  \"from_dhcp_options\" : true,\n"
              "  \"servers\" : \n"
              "  {\n"
              "    \"0\" : \n"
              "    {\n"
              "      \"addresses\" : \n"
              "      [\n"
              "        {\n"
              "          \"address\" : \"1::1\"\n"
              "        }\n"
              "      ]\n"
              "    }\n"
              "  }\n"
              "}");

    DnsOptions fromJson;
    fromJson.from_json(json, "json test");
    ASSERT_EQ(fromJson.to_string(),
              "DNS Servers:\n"
              "  Priority: 0\n"
              "  Addresses:\n"
              "    1::1\n"
              "Values from dhcp-options: true\n");
}

TEST(Dns, JsonRoundtripAllValuesSet)
{
    OptionList config;
    config.parse_from_config(
        "dns search-domains dom1 dom2 dom3\n"
        "dns server 10 address 1::1 1.1.1.1\n"
        "dns server 10 resolve-domains rdom11 rdom12\n"
        "dns server 10 transport DoT\n"
        "dns server 10 sni snidom1\n"
        "dns server 10 dnssec optional\n"
        "dns server 20 address [2::2]:5353 2.2.2.2:5353\n"
        "dns server 20 resolve-domains rdom21 rdom22\n"
        "dns server 20 transport DoH\n"
        "dns server 20 sni snidom2\n"
        "dns server 20 dnssec yes\n",
        nullptr);
    config.update_map();
    DnsOptionsParser toJson(config, false);
    Json::Value json = toJson.to_json();
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    ASSERT_EQ(Json::writeString(builder, json),
              "{\n"
              "  \"from_dhcp_options\" : false,\n"
              "  \"search_domains\" : \n"
              "  [\n"
              "    \"dom1\",\n"
              "    \"dom2\",\n"
              "    \"dom3\"\n"
              "  ],\n"
              "  \"servers\" : \n"
              "  {\n"
              "    \"10\" : \n"
              "    {\n"
              "      \"addresses\" : \n"
              "      [\n"
              "        {\n"
              "          \"address\" : \"1::1\"\n"
              "        },\n"
              "        {\n"
              "          \"address\" : \"1.1.1.1\"\n"
              "        }\n"
              "      ],\n"
              "      \"dnssec\" : \"Optional\",\n"
              "      \"domains\" : \n"
              "      [\n"
              "        \"rdom11\",\n"
              "        \"rdom12\"\n"
              "      ],\n"
              "      \"sni\" : \"snidom1\",\n"
              "      \"transport\" : \"TLS\"\n"
              "    },\n"
              "    \"20\" : \n"
              "    {\n"
              "      \"addresses\" : \n"
              "      [\n"
              "        {\n"
              "          \"address\" : \"2::2\",\n"
              "          \"port\" : 5353\n"
              "        },\n"
              "        {\n"
              "          \"address\" : \"2.2.2.2\",\n"
              "          \"port\" : 5353\n"
              "        }\n"
              "      ],\n"
              "      \"dnssec\" : \"Yes\",\n"
              "      \"domains\" : \n"
              "      [\n"
              "        \"rdom21\",\n"
              "        \"rdom22\"\n"
              "      ],\n"
              "      \"sni\" : \"snidom2\",\n"
              "      \"transport\" : \"HTTPS\"\n"
              "    }\n"
              "  }\n"
              "}");

    DnsOptions fromJson;
    fromJson.from_json(json, "json test");
    ASSERT_EQ(fromJson.to_string(),
              "DNS Servers:\n"
              "  Priority: 10\n"
              "  Addresses:\n"
              "    1::1\n"
              "    1.1.1.1\n"
              "  Domains:\n"
              "    rdom11\n"
              "    rdom12\n"
              "  DNSSEC: Optional\n"
              "  Transport: TLS\n"
              "  SNI: snidom1\n"
              "  Priority: 20\n"
              "  Addresses:\n"
              "    [2::2]:5353\n"
              "    2.2.2.2:5353\n"
              "  Domains:\n"
              "    rdom21\n"
              "    rdom22\n"
              "  DNSSEC: Yes\n"
              "  Transport: HTTPS\n"
              "  SNI: snidom2\n"
              "DNS Search Domains:\n"
              "  dom1\n"
              "  dom2\n"
              "  dom3\n"
              "Values from dhcp-options: false\n");
}

} // namespace unittests