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

// Tests for parsing remote-cert-tls, remote-cert-ku and remote-cert-eku.

#include "test_common.hpp"

#include <openvpn/common/options.hpp>
#include <openvpn/ssl/kuparse.hpp>

using namespace openvpn;

namespace {

const std::string server_auth = "TLS Web Server Authentication";
const std::string client_auth = "TLS Web Client Authentication";

/**
 * @brief What KUParse::remote_cert() parsed.
 */
struct Parsed
{
    std::vector<unsigned int> ku; ///< key usage values, empty for no check
    std::string eku;              ///< extended key usage, empty for no check
};

/**
 * @brief KUParse::remote_cert() on a profile's text.
 */
Parsed parse(const std::string &profile, const std::string &relay_prefix = "")
{
    Parsed ret;
    KUParse::remote_cert(OptionList::parse_from_config_static(profile, nullptr), relay_prefix, ret.ku, ret.eku);
    return ret;
}

} // namespace

TEST(KUParse, RemoteCertTlsServer)
{
    const Parsed p = parse("remote-cert-tls server\n");
    EXPECT_EQ(p.ku, std::vector<unsigned int>{KUParse::KU_REQUIRED});
    EXPECT_EQ(p.eku, server_auth);
}

TEST(KUParse, RemoteCertTlsClient)
{
    const Parsed p = parse("remote-cert-tls client\n");
    EXPECT_EQ(p.ku, std::vector<unsigned int>{KUParse::KU_REQUIRED});
    EXPECT_EQ(p.eku, client_auth);
}

TEST(KUParse, NoDirectives)
{
    const Parsed p = parse("client\n");
    EXPECT_TRUE(p.ku.empty());
    EXPECT_TRUE(p.eku.empty());
}

TEST(KUParse, EkuOverridesRemoteCertTlsInEitherOrder)
{
    for (const char *profile : {"remote-cert-tls server\nremote-cert-eku 1.3.6.1.5.5.7.3.1\n",
                                "remote-cert-eku 1.3.6.1.5.5.7.3.1\nremote-cert-tls server\n"})
    {
        const Parsed p = parse(profile);
        EXPECT_EQ(p.ku, std::vector<unsigned int>{KUParse::KU_REQUIRED}) << profile;
        EXPECT_EQ(p.eku, "1.3.6.1.5.5.7.3.1") << profile;
    }
}

TEST(KUParse, EmptyEku)
{
    OVPN_EXPECT_THROW(parse("remote-cert-tls server\nremote-cert-eku \"\"\n"), option_error, "remote-cert-eku");
    OVPN_EXPECT_THROW(parse("remote-cert-eku ''\n"), option_error, "remote-cert-eku");
    OVPN_EXPECT_THROW(parse("remote-cert-eku\n"), option_error, "remote-cert-eku");
}

TEST(KUParse, KuOverridesRemoteCertTlsInEitherOrder)
{
    for (const char *profile : {"remote-cert-tls server\nremote-cert-ku a0 88\n",
                                "remote-cert-ku a0 88\nremote-cert-tls server\n"})
    {
        const Parsed p = parse(profile);
        EXPECT_EQ(p.ku, (std::vector<unsigned int>{0xa0, 0x88})) << profile;
        EXPECT_EQ(p.eku, server_auth) << profile;
    }
}

TEST(KUParse, KuAlone)
{
    const Parsed p = parse("remote-cert-ku 80\n");
    EXPECT_EQ(p.ku, std::vector<unsigned int>{0x80});
    EXPECT_TRUE(p.eku.empty());
}

TEST(KUParse, BareKuRequiresTheExtension)
{
    const Parsed p = parse("remote-cert-ku\n");
    EXPECT_EQ(p.ku, std::vector<unsigned int>{KUParse::KU_REQUIRED});
    EXPECT_TRUE(p.eku.empty());
}

TEST(KUParse, KuValuesUseBits80To02)
{
    const Parsed p = parse("remote-cert-ku fe 2\n");
    EXPECT_EQ(p.ku, (std::vector<unsigned int>{0xfe, 0x02}));
}

TEST(KUParse, BadKuValues)
{
    // 0 would match any certificate, and so would 1 and 8000 on mbed TLS,
    // which treats them as optional
    for (const char *values : {"0", "a0 0", "1", "81", "ff", "8000", "100", "ffff", "1000000a0", "zz"})
    {
        OVPN_EXPECT_THROW(parse(std::string("remote-cert-ku ") + values + "\n"), option_error, "remote-cert-ku");
    }
}

TEST(KUParse, BadRemoteCertTls)
{
    OVPN_EXPECT_THROW(parse("remote-cert-tls bogus\n"), option_error, "remote-cert-tls");
    OVPN_EXPECT_THROW(parse("remote-cert-tls\n"), option_error, "remote-cert-tls");
}

TEST(KUParse, RelayPrefix)
{
    const std::string profile = "relay-remote-cert-tls server\n";

    const Parsed relay = parse(profile, "relay-");
    EXPECT_EQ(relay.ku, std::vector<unsigned int>{KUParse::KU_REQUIRED});
    EXPECT_EQ(relay.eku, server_auth);

    const Parsed plain = parse(profile);
    EXPECT_TRUE(plain.ku.empty());
    EXPECT_TRUE(plain.eku.empty());
}

TEST(KUParse, ReparseLeavesNoStaleValues)
{
    std::vector<unsigned int> ku;
    std::string eku;

    KUParse::remote_cert(OptionList::parse_from_config_static("remote-cert-ku a0\nremote-cert-eku 1.2.3\n", nullptr), "", ku, eku);
    KUParse::remote_cert(OptionList::parse_from_config_static("client\n", nullptr), "", ku, eku);
    EXPECT_TRUE(ku.empty());
    EXPECT_TRUE(eku.empty());
}
