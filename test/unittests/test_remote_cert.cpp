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

// Tests for the peer certificate checks behind remote-cert-tls, remote-cert-ku
// and remote-cert-eku. The certificates come from test/ssl/gen-ku-certs.sh.

#include "test_common.hpp"

#include <openvpn/common/file.hpp>
#include <openvpn/ssl/kuparse.hpp>
#include <openvpn/ssl/sslchoose.hpp>

using namespace openvpn;

namespace {

/**
 * @brief Reads test/ssl/<name>.crt.
 */
std::string test_cert(const std::string &name)
{
    return read_text(std::string(UNITTEST_SOURCE_DIR "/../ssl/") + name + ".crt");
}

/**
 * @brief The remote-cert-ku check on test/ssl/<name>.crt.
 */
bool ku_ok(const std::vector<unsigned int> &ku, const std::string &name)
{
    return SSLLib::SSLAPI::check_x509_cert_ku(ku, test_cert(name));
}

/**
 * @brief The remote-cert-eku check on test/ssl/<name>.crt.
 */
bool eku_ok(const std::string &eku, const std::string &name)
{
    return SSLLib::SSLAPI::check_x509_cert_eku(eku, test_cert(name));
}

const std::string server_auth = "TLS Web Server Authentication";

} // namespace

TEST(RemoteCert, KuRequiredOnlyNeedsTheExtension)
{
    for (const char *name : {"server", "server-noeku", "server-ds", "server-a8", "server-anyeku", "server-clienteku", "client-eku"})
        EXPECT_TRUE(ku_ok({KUParse::KU_REQUIRED}, name)) << name;

    EXPECT_FALSE(ku_ok({KUParse::KU_REQUIRED}, "server-noku"));
    EXPECT_FALSE(ku_ok({KUParse::KU_REQUIRED}, "client"));
}

TEST(RemoteCert, KuNeedsEveryBitOfOneValue)
{
    EXPECT_TRUE(ku_ok({0xa0}, "server"));
    EXPECT_TRUE(ku_ok({0xa0}, "server-a8"));
    EXPECT_FALSE(ku_ok({0xa0}, "server-ds"));
    EXPECT_FALSE(ku_ok({0xa0}, "server-noku"));

    EXPECT_TRUE(ku_ok({0x88}, "server-a8"));
    EXPECT_FALSE(ku_ok({0x88}, "server"));
    EXPECT_FALSE(ku_ok({0x88}, "server-ds"));

    EXPECT_TRUE(ku_ok({0xa0, 0x88}, "server"));
    EXPECT_TRUE(ku_ok({0xa0, 0x88}, "server-a8"));
    EXPECT_FALSE(ku_ok({0xa0, 0x88}, "server-ds"));

    EXPECT_TRUE(ku_ok({0x80}, "server-ds"));
    EXPECT_TRUE(ku_ok({0x80}, "server"));
}

TEST(RemoteCert, KuZeroMatchesNothing)
{
    EXPECT_FALSE(ku_ok({0}, "server"));
    EXPECT_TRUE(ku_ok({0, 0xa0}, "server"));
}

TEST(RemoteCert, EkuByName)
{
    for (const char *name : {"server", "server-noku", "server-ds", "server-a8"})
        EXPECT_TRUE(eku_ok(server_auth, name)) << name;

    for (const char *name : {"server-noeku", "server-anyeku", "server-clienteku", "client", "client-eku"})
        EXPECT_FALSE(eku_ok(server_auth, name)) << name;

    EXPECT_TRUE(eku_ok("TLS Web Client Authentication", "client-eku"));
    EXPECT_FALSE(eku_ok("TLS Web Client Authentication", "server"));
}

TEST(RemoteCert, EkuByOid)
{
    EXPECT_TRUE(eku_ok("1.3.6.1.5.5.7.3.1", "server"));
    EXPECT_FALSE(eku_ok("1.3.6.1.5.5.7.3.1", "server-clienteku"));
    EXPECT_TRUE(eku_ok("1.3.6.1.5.5.7.3.2", "client-eku"));
}
