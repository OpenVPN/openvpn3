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
// and remote-cert-eku: alone, then through SSLConfigAPI::load() and a handshake.
// The certificates come from test/ssl/gen-ku-certs.sh.

#include "test_common.hpp"

#include <algorithm>

#include <openvpn/common/file.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/ssl/kuparse.hpp>
#include <openvpn/ssl/sslchoose.hpp>

using namespace openvpn;

namespace {

/**
 * @brief Reads test/ssl/<name>.
 */
std::string test_file(const std::string &name)
{
    return read_text(std::string(UNITTEST_SOURCE_DIR "/../ssl/") + name);
}

/**
 * @brief Reads test/ssl/<name>.crt.
 */
std::string test_cert(const std::string &name)
{
    return test_file(name + ".crt");
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

/**
 * @brief A profile of @p directives that trusts the test CA and presents
 *        test/ssl/<name>.crt and .key.
 */
std::string profile(const std::string &directives, const std::string &name)
{
    return directives
           + "<ca>\n" + test_file("ca.crt") + "</ca>\n"
           + "<cert>\n" + test_file(name + ".crt") + "</cert>\n"
           + "<key>\n" + test_file(name + ".key") + "</key>\n";
}

/**
 * @brief A TLS session set up the way a client or server loads its profile.
 */
struct Endpoint
{
    /**
     * @brief Loads @p profile_txt with SSLConfigAPI::load(); a "client"
     *        directive makes it the client.
     */
    explicit Endpoint(const std::string &profile_txt)
        : config(new SSLLib::SSLAPI::Config)
    {
        config->set_frame(Frame::Ptr(new Frame(Frame::Context(128, 4096, 4096 - 128, 0, 16, 0))));
        config->set_rng(StrongRandomAPI::Ptr(new SSLLib::RandomAPI()));
        config->load(OptionList::parse_from_config_static(profile_txt, nullptr), SSLConfigAPI::LF_PARSE_MODE);
        factory = config->new_factory();
        ssl = factory->ssl();
    }

    SSLLib::SSLAPI::Config::Ptr config;
    SSLFactoryAPI::Ptr factory;
    SSLAPI::Ptr ssl;
    std::string received; ///< cleartext read so far
};

/**
 * @brief Delivers @p from's pending ciphertext to @p to, which processes it and
 *        appends any cleartext to its received.
 *
 * @return true if any ciphertext moved
 */
bool deliver(Endpoint &from, Endpoint &to)
{
    bool moved = false;
    while (from.ssl->read_ciphertext_ready())
    {
        to.ssl->write_ciphertext(from.ssl->read_ciphertext());
        moved = true;
    }

    // reading is what drives the handshake
    while (to.ssl->read_cleartext_ready())
    {
        char buf[256];
        const ssize_t n = to.ssl->read_cleartext(buf, sizeof(buf));
        if (n <= 0)
            break;
        to.received.append(buf, static_cast<size_t>(n));
    }
    return moved;
}

/**
 * @brief Runs a handshake, then sends a message from client to server.
 *
 * @return true if the server received it
 */
bool connect(Endpoint &client, Endpoint &server)
{
    const std::string msg = "ping";
    try
    {
        client.ssl->start_handshake();
        server.ssl->start_handshake();
        while (deliver(client, server) || deliver(server, client))
            ;

        if (client.ssl->write_cleartext_unbuffered(msg.data(), msg.size()) != static_cast<ssize_t>(msg.size()))
            return false;
        while (deliver(client, server) || deliver(server, client))
            ;
    }
    catch (const std::exception &e)
    {
        std::cout << "connect failed: " << e.what() << '\n';
        return false;
    }
    return server.received == msg;
}

/**
 * @brief Checks that connect() fails and logs @p reason.
 */
testing::AssertionResult rejected_for(Endpoint &client, Endpoint &server, const std::string &reason)
{
    // the level is shared and other tests change it
    const int level = SSLFactoryAPI::log_level();
    SSLFactoryAPI::set_log_level(std::max(level, logging::LOG_LEVEL_INFO));
    testLog->startCollecting();
    const bool connected = connect(client, server);
    const std::string log = testLog->stopCollecting();
    SSLFactoryAPI::set_log_level(level);

    if (connected)
        return testing::AssertionFailure() << "handshake succeeded";
    if (log.find(reason) == std::string::npos)
        return testing::AssertionFailure() << "\"" << reason << "\" not in log:\n"
                                           << log;
    return testing::AssertionSuccess();
}

const std::string bad_ku = "VERIFY FAIL -- bad X509 key usage";
const std::string bad_eku = "VERIFY FAIL -- bad X509 extended key usage";

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

TEST(RemoteCert, ProfileWithoutDirectivesAcceptsServerWithoutEku)
{
    Endpoint server(profile("", "server-noeku"));
    Endpoint client(profile("client\n", "client"));
    EXPECT_TRUE(connect(client, server));
}

TEST(RemoteCert, ProfileWithoutDirectivesAcceptsServerWithoutKu)
{
    Endpoint server(profile("", "server-noku"));
    Endpoint client(profile("client\n", "client"));
    EXPECT_TRUE(connect(client, server));
}

TEST(RemoteCert, ProfileRemoteCertTlsServerAcceptsServerCert)
{
    Endpoint server(profile("", "server"));
    Endpoint client(profile("client\nremote-cert-tls server\n", "client"));
    EXPECT_TRUE(connect(client, server));
}

TEST(RemoteCert, ProfileRemoteCertTlsServerRejectsServerWithoutEku)
{
    Endpoint server(profile("", "server-noeku"));
    Endpoint client(profile("client\nremote-cert-tls server\n", "client"));
    EXPECT_TRUE(rejected_for(client, server, bad_eku));
}

TEST(RemoteCert, ProfileRemoteCertTlsServerRejectsServerWithoutKu)
{
    Endpoint server(profile("", "server-noku"));
    Endpoint client(profile("client\nremote-cert-tls server\n", "client"));
    EXPECT_TRUE(rejected_for(client, server, bad_ku));
}

TEST(RemoteCert, ProfileRemoteCertTlsClientAcceptsClientCert)
{
    Endpoint server(profile("remote-cert-tls client\n", "server"));
    Endpoint client(profile("client\n", "client-eku"));
    EXPECT_TRUE(connect(client, server));
}

TEST(RemoteCert, ProfileRemoteCertTlsClientRejectsClientWithoutUsage)
{
    Endpoint server(profile("remote-cert-tls client\n", "server"));
    Endpoint client(profile("client\n", "client"));
    EXPECT_TRUE(rejected_for(client, server, bad_ku));
}
