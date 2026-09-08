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

#include <openvpn/ssl/sslchoose.hpp>


#include <openvpn/ssl/sslapi.hpp>

using namespace openvpn;

const std::string pvt_key_txt = R"(-----BEGIN PRIVATE KEY-----
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
NP5tGsFi4iV5VR2DHQd+Z/5Cbe2Y
-----END PRIVATE KEY-----)";

const std::string fail_pvt_key_txt = R"(-----BEGIN PRIVATE KEY-----
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
1vEcBD3rxLEh4uavbzumhBFCGZuIWg==
-----END PRIVATE KEY-----)";

const std::string cert_txt = R"(-----BEGIN CERTIFICATE-----
MIIFwTCCA6mgAwIBAgIUcRBdLp7xIk5v+o4Akel9SMTXKHIwDQYJKoZIhvcNAQEL
BQAwcDELMAkGA1UEBhMCWFgxEjAQBgNVBAgMCVN0YXRlTmFtZTENMAsGA1UEBwwE
Q2l0eTEQMA4GA1UECgwHQ29tcGFueTEXMBUGA1UECwwOQ29tcGFueVNlY3Rpb24x
EzARBgNVBAMMCkNvbW1vbk5hbWUwHhcNMjMxMjIwMDYxNzI5WhcNMzMxMjE3MDYx
NzI5WjBwMQswCQYDVQQGEwJYWDESMBAGA1UECAwJU3RhdGVOYW1lMQ0wCwYDVQQH
DARDaXR5MRAwDgYDVQQKDAdDb21wYW55MRcwFQYDVQQLDA5Db21wYW55U2VjdGlv
bjETMBEGA1UEAwwKQ29tbW9uTmFtZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAMs/NuacorWP0wZQ2cvYehIBVJtU0VNalZaWhSdhck4QphdxGF4yjs9F
IYmSRuzyhjrJU0OSWu3o8VBVlPnY6PCIFNpRdA+FPQK0SkXXQdoqF77WGTX8/cRC
OSmmJiiE0eQ1bNQ4AOZ0gnlPaB7Iu3qH3go58rq1h73Wx83muXf1nCS286ryHBIp
IUeoCkI/2CdHTxh3FdjldvbWabDTuJbEGdDEa2Xmi+GyxZ7ci5VQd4AgYQnE1eJR
KbtJUHqgNIod/GIcj1RRcZeUMlRO5JXh6WViWpyz8f/r5bIzm3s0w+hEtMjDv5oW
8JcE8uQgj+68VZv6Kuw7UgJdJwgUQBE3Vbm+raMbUL2HlJF8yGkAuCtR+2JQJiyd
AWhpzVeisfughiRAYu/5RK9s4qv5P5MSo31ox0LigX989umzchcGovX2maGnXylr
ddfJ1K+tH64LJkTQ6XzDcl/n6babxmYNMLmKv8/LWVYXWf6q5gzH9/SFl24lSrp4
7/E1moRsbOrv9g2bj89RIKR1Ro7is7pWgZZdWGaHuo/+7f83Z97bK/uqoYQFegGg
OPCVUGJnALxkPF8KRmi+wKQAAC1RYz++Y14UfUaHQE/PxRgw8j0JaoGK7LQya2Ko
SuOtBlZAnNsnZpz813smrQw3XdHVT08jKIaNkuVU6xFZ++AayKz/AgMBAAGjUzBR
MB0GA1UdDgQWBBSPFAV7oBThf2t85aaxUs3vWLjk1jAfBgNVHSMEGDAWgBSPFAV7
oBThf2t85aaxUs3vWLjk1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4ICAQBiXfCdKAZtNT1wYeuE1b5bOoWtDFbkSiZ/9iT8rpyjhxbkTviXPAY3okF+
PRRZT+6wEXQ1Wh0ymRW+nDvAewxSi8c7ry+xcHLI25tHxfJDafk5LwiNsDSGwc+T
wISXJ5LrHy9XqESJD3ZtLFal8zIYJmd7Rp8zUF7Qx44qzpKOsM3udwIGihO14RkQ
5wbUok/N1Z/wmswdcCji79aU69LrSWewld2gLuguogUVReC/S1hziSgud0EukZoo
btLKaVrsxZanXk/v7ijyZuD7MN32dbfPPYR3eCUf1/kNutNrgjPh0xRLi9pr/KC6
62FrN/WanYurrQYQj721XZgNeq8fyuCNc/SY6vEbimXq9Orx7oBI5PTxaSuDmDaX
DRIkmuf9o1OeWTPGjY4+/O/DYGDSbkHqbGqpUEMD1vP7Ui0wzJbAdhJ+ar7hW0DS
LoeD6wYEov9ArKnFnyHsD/eVwQGZNjYP9qjzXUv51Uzsyw8207njrGZFWUfWC0tl
oCCmFIz0tu4A63+ieiyUvDB9HzHx6QHBC60uDh+pKCK7TRg3yAZ+pg5W6Nkk8NTZ
v5DxppHxwZoZtdnQPKc13ax1UNpYibQYAh98B1tvHs95gd2oOdRFGeg5O9aVJcxl
da0X3BFsTH3RvZEyQcx8hiUsBqP9vh1SmC7TJvdCjuAZVnaT/A==
-----END CERTIFICATE-----)";

const std::string fail_cert_txt = R"(-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----)";

const std::string certcrl_txt = R"(-----BEGIN CERTIFICATE-----
MIIFwTCCA6mgAwIBAgIUcRBdLp7xIk5v+o4Akel9SMTXKHIwDQYJKoZIhvcNAQEL
BQAwcDELMAkGA1UEBhMCWFgxEjAQBgNVBAgMCVN0YXRlTmFtZTENMAsGA1UEBwwE
Q2l0eTEQMA4GA1UECgwHQ29tcGFueTEXMBUGA1UECwwOQ29tcGFueVNlY3Rpb24x
EzARBgNVBAMMCkNvbW1vbk5hbWUwHhcNMjMxMjIwMDYxNzI5WhcNMzMxMjE3MDYx
NzI5WjBwMQswCQYDVQQGEwJYWDESMBAGA1UECAwJU3RhdGVOYW1lMQ0wCwYDVQQH
DARDaXR5MRAwDgYDVQQKDAdDb21wYW55MRcwFQYDVQQLDA5Db21wYW55U2VjdGlv
bjETMBEGA1UEAwwKQ29tbW9uTmFtZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAMs/NuacorWP0wZQ2cvYehIBVJtU0VNalZaWhSdhck4QphdxGF4yjs9F
IYmSRuzyhjrJU0OSWu3o8VBVlPnY6PCIFNpRdA+FPQK0SkXXQdoqF77WGTX8/cRC
OSmmJiiE0eQ1bNQ4AOZ0gnlPaB7Iu3qH3go58rq1h73Wx83muXf1nCS286ryHBIp
IUeoCkI/2CdHTxh3FdjldvbWabDTuJbEGdDEa2Xmi+GyxZ7ci5VQd4AgYQnE1eJR
KbtJUHqgNIod/GIcj1RRcZeUMlRO5JXh6WViWpyz8f/r5bIzm3s0w+hEtMjDv5oW
8JcE8uQgj+68VZv6Kuw7UgJdJwgUQBE3Vbm+raMbUL2HlJF8yGkAuCtR+2JQJiyd
AWhpzVeisfughiRAYu/5RK9s4qv5P5MSo31ox0LigX989umzchcGovX2maGnXylr
ddfJ1K+tH64LJkTQ6XzDcl/n6babxmYNMLmKv8/LWVYXWf6q5gzH9/SFl24lSrp4
7/E1moRsbOrv9g2bj89RIKR1Ro7is7pWgZZdWGaHuo/+7f83Z97bK/uqoYQFegGg
OPCVUGJnALxkPF8KRmi+wKQAAC1RYz++Y14UfUaHQE/PxRgw8j0JaoGK7LQya2Ko
SuOtBlZAnNsnZpz813smrQw3XdHVT08jKIaNkuVU6xFZ++AayKz/AgMBAAGjUzBR
MB0GA1UdDgQWBBSPFAV7oBThf2t85aaxUs3vWLjk1jAfBgNVHSMEGDAWgBSPFAV7
oBThf2t85aaxUs3vWLjk1jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4ICAQBiXfCdKAZtNT1wYeuE1b5bOoWtDFbkSiZ/9iT8rpyjhxbkTviXPAY3okF+
PRRZT+6wEXQ1Wh0ymRW+nDvAewxSi8c7ry+xcHLI25tHxfJDafk5LwiNsDSGwc+T
wISXJ5LrHy9XqESJD3ZtLFal8zIYJmd7Rp8zUF7Qx44qzpKOsM3udwIGihO14RkQ
5wbUok/N1Z/wmswdcCji79aU69LrSWewld2gLuguogUVReC/S1hziSgud0EukZoo
btLKaVrsxZanXk/v7ijyZuD7MN32dbfPPYR3eCUf1/kNutNrgjPh0xRLi9pr/KC6
62FrN/WanYurrQYQj721XZgNeq8fyuCNc/SY6vEbimXq9Orx7oBI5PTxaSuDmDaX
DRIkmuf9o1OeWTPGjY4+/O/DYGDSbkHqbGqpUEMD1vP7Ui0wzJbAdhJ+ar7hW0DS
LoeD6wYEov9ArKnFnyHsD/eVwQGZNjYP9qjzXUv51Uzsyw8207njrGZFWUfWC0tl
oCCmFIz0tu4A63+ieiyUvDB9HzHx6QHBC60uDh+pKCK7TRg3yAZ+pg5W6Nkk8NTZ
v5DxppHxwZoZtdnQPKc13ax1UNpYibQYAh98B1tvHs95gd2oOdRFGeg5O9aVJcxl
da0X3BFsTH3RvZEyQcx8hiUsBqP9vh1SmC7TJvdCjuAZVnaT/A==
-----END CERTIFICATE-----)";

const std::string dhparam_txt = R"(-----BEGIN DH PARAMETERS-----
MIIBDAKCAQEA9WXZvihl5pltdS4C+Dc+Ki3KOuH0aBfSzmth/B3O0+oTN3CZXAak
WyK6dCCtXeBZ3ih3eNVO69BgoNVdbxuPIUWxo3EWFt6LteASgkjCEyTmrNd/aKAE
pS06RgsZcWs/Ps9iwcVFyE6kMi9Cbf3D2wwJT50kJmkEov+4cOH3NQVpS231I58x
rHMEMtNDFcJYCAEIG3cKqfX9unAgZUsDoLtyvfgvHV29koZxnmMt0+5f0qnezcnP
I/+4kAlXuAKdhsXohHeBhC2ijg/kTOMDxEbEVv+SkCIUyM+dB8UtlPKOH9HEL5Xi
+BpDSqO6Bha5+NAVUU7OdDsnzRwSWaD6lwIBAgICAOE=
-----END DH PARAMETERS-----)";

TEST(sslctx_ut, create_config)
{
    SSLLib::SSLAPI::Config::Ptr config = new SSLLib::SSLAPI::Config;
    // Do not log extra data during unit test
    config->set_debug_level(0);
    EXPECT_TRUE(config);
}

TEST(sslctx_ut, config_new_factory_server)
{
    SSLLib::SSLAPI::Config::Ptr config = new SSLLib::SSLAPI::Config;
    EXPECT_TRUE(config);

    StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());
    config->set_rng(rng);

    config->set_mode(Mode(Mode::SERVER));
    config->load_cert(cert_txt);
    config->load_private_key(pvt_key_txt);
    config->load_ca(cert_txt, false);

    // Do not log extra data during unit test
    config->set_debug_level(0);

    auto factory_server = config->new_factory();
    EXPECT_TRUE(factory_server);

    auto server = factory_server->ssl();
    EXPECT_TRUE(server);
}

TEST(sslctx_ut, config_new_factory_client)
{
    SSLLib::SSLAPI::Config::Ptr config = new SSLLib::SSLAPI::Config;
    EXPECT_TRUE(config);

    StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());
    config->set_rng(rng);

    config->set_mode(Mode(Mode::CLIENT));
    config->load_cert(cert_txt);
    config->load_private_key(pvt_key_txt);
    config->load_ca(cert_txt, false);

    // Do not log extra data during unit test
    config->set_debug_level(0);

    auto factory_client = config->new_factory();
    EXPECT_TRUE(factory_client);

    auto client = factory_client->ssl();
    EXPECT_TRUE(client);
}

#define ITER 1000
#define ITER_OUT_LIMIT 1000

// From ovpn3/common/test/osx/ssl.cpp
template <typename T>
inline void do_write(T &obj, const bool server, char *msg, const size_t len, long &count, const int iter)
{
    const ssize_t status = obj.write_cleartext_unbuffered(msg, len);
    if (status > 0)
        count += status;
#if ITER <= ITER_OUT_LIMIT
    std::cout << (server ? "SERVER" : "CLIENT") << " WRITE #" << iter << " status=" << status << std::endl;
#endif
}

template <typename T>
inline void do_read(T &obj, const bool server, char *msg, const size_t len, long &count, const int iter)
{
    const ssize_t status = obj.read_cleartext(msg, len);
    if (status > 0)
        count += status;

#if ITER <= ITER_OUT_LIMIT
    const ssize_t trunc = 64;
    std::cout << (server ? "SERVER" : "CLIENT") << " READ #" << iter << " status=" << status << std::endl;
    if (status >= trunc)
    {
        msg[trunc] = 0;
        std::cout << "GOT IT: " << msg << std::endl;
    }
#endif
}

static inline bool xfer_oneway(SSLAPI &sender, SSLAPI &recv, std::string out)
{
    if (sender.read_ciphertext_ready())
    {
        BufferPtr buf = sender.read_ciphertext();
        recv.write_ciphertext(buf);
        std::cout << out << buf->size() << " bytes" << std::endl;
        return true;
    }

    if (sender.read_cleartext_ready())
    {
        /* this can also indicate an error */
        uint8_t cleartext[1024];

        std::cout << out << " read ready?" << std::endl;
        auto ctsize = sender.read_cleartext(cleartext, sizeof(cleartext));
        std::cout << ctsize << std::endl;

        EXPECT_FALSE(ctsize > 0);
        /* TODO: capture output for tests with data */
        return true;
    }
    return false;
}

static inline void xfer(SSLAPI &cli, SSLAPI &serv)
{
    while (xfer_oneway(cli, serv, "CLIENT -> SERVER ") || xfer_oneway(serv, cli, "SERVER -> CLIENT"))
    {
        /* while we have done work, keep working */
    }
}

static inline auto MakeClient(Frame::Ptr frame,
                              const std::string &pvt_key,
                              const std::string &cert,
                              const std::string &ca = "")
{
    SSLLib::SSLAPI::Config::Ptr config = new SSLLib::SSLAPI::Config;
    EXPECT_TRUE(config);

    StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());
    config->set_rng(rng);

    config->set_mode(Mode(Mode::CLIENT));
    config->load_cert(cert);
    config->load_private_key(pvt_key);
    config->set_frame(frame);
    if (ca.empty())
    {
        std::cout << "No CA for client\n";
        config->set_flags(SSLConfigAPI::LF_ALLOW_CLIENT_CERT_NOT_REQUIRED);
    }
    else
        config->load_ca(ca, false);

    auto factory_client = config->new_factory();
    EXPECT_TRUE(factory_client);

    auto client = factory_client->ssl();
    EXPECT_TRUE(client);

    return std::make_tuple(config, factory_client, client);
}

static inline auto MakeServer(Frame::Ptr frame,
                              const std::string &pvt_key,
                              const std::string &cert,
                              const std::string &ca = "")
{
    SSLLib::SSLAPI::Config::Ptr config = new SSLLib::SSLAPI::Config;
    config->enable_legacy_algorithms(false);
    EXPECT_TRUE(config);

    StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());
    config->set_rng(rng);

    config->set_mode(Mode(Mode::SERVER));
    config->load_cert(cert);
    config->load_private_key(pvt_key);
    config->load_ca(ca.empty() ? cert : ca, false);
    config->set_frame(frame);
    config->load_dh(dhparam_txt);

    auto factory_server = config->new_factory();
    EXPECT_TRUE(factory_server);

    auto server = factory_server->ssl();
    EXPECT_TRUE(server);

    return std::make_tuple(config, factory_server, server);
}

TEST(sslctx_ut, handshake)
{
    Frame::Ptr frame(new Frame(Frame::Context(128, 4096, 4096 - 128, 0, 16, 0)));
    auto [serverconfig, serverfactory, server] = MakeServer(frame, pvt_key_txt, cert_txt);
    auto [clientconfig, clientfactory, client] = MakeClient(std::move(frame), pvt_key_txt, cert_txt);

    // Some internal state that's inside these objects seems required for ssl to work
    // serverconfig.reset();
    // serverfactory.reset();
    // clientconfig.reset();
    // clientfactory.reset();

    client->start_handshake();

    try
    {
        for (auto i = 0u; i < ITER; ++i)
        {
            xfer(*client, *server);
        }
    }
    catch (...)
    {
        FAIL();
    }
}

TEST(sslctx_ut, ca_handshake)
{
    Frame::Ptr frame(new Frame(Frame::Context(128, 4096, 4096 - 128, 0, 16, 0)));
    auto [serverconfig, serverfactory, server] = MakeServer(frame, pvt_key_txt, cert_txt);
    auto [clientconfig, clientfactory, client] = MakeClient(std::move(frame), pvt_key_txt, cert_txt, cert_txt);

    // Some internal state that's inside these objects seems required for ssl to work
    // serverconfig.reset();
    // serverfactory.reset();
    // clientconfig.reset();
    // clientfactory.reset();

    client->start_handshake();

    try
    {
        for (auto i = 0u; i < ITER; ++i)
        {
            xfer(*client, *server);
        }
    }
    catch (...)
    {
        FAIL();
    }
}

TEST(sslctx_ut, handshake_fail)
{
    Frame::Ptr frame(new Frame(Frame::Context(128, 4096, 4096 - 128, 0, 16, 0)));
    auto [serverconfig, serverfactory, server] = MakeServer(frame, fail_pvt_key_txt, fail_cert_txt);
    auto [clientconfig, clientfactory, client] = MakeClient(std::move(frame), pvt_key_txt, cert_txt);

    client->start_handshake();

    try
    {
        for (auto i = 0u; i < ITER; ++i)
        {
            xfer(*client, *server);
        }
    }
    catch (...)
    {
        // Oddly enough, these return true even though a full handshake did not happen
        // EXPECT_FALSE(client->did_full_handshake());
        // EXPECT_FALSE(server->did_full_handshake());
        return;
    }
    FAIL();
}

TEST(sslctx_ut, clienthello)
{
    /* Checks that a server context correctly responds to a TLS 1.3 client hello */
    uint8_t clienthello[] = {
        0x16, 0x03, 0x01, 0x01, 0x10, 0x01, 0x00, 0x01, 0x0c, 0x03, 0x03, 0x0a, 0xef, 0xce, 0xc6, 0xe3, 0xcc, 0xb7, 0x7c, 0x38, 0xb2, 0x0e, 0xac, 0x12, 0xb5, 0xfa, 0x6d, 0x98, 0xc7, 0x76, 0xd1, 0x96, 0x22, 0x97, 0xf5, 0x57, 0xc5, 0x12, 0xf7, 0x01, 0xfc, 0xbe, 0x7d, 0x20, 0x64, 0xbd, 0xb5, 0x68, 0x06, 0x55, 0xb1, 0xf3, 0xf3, 0xc7, 0xb4, 0x1b, 0xbe, 0x83, 0x89, 0xab, 0xa5, 0xa0, 0x55, 0xa5, 0x6d, 0xca, 0xb1, 0x21, 0x5f, 0x2c, 0x71, 0xf5, 0x13, 0x4d, 0xeb, 0x68, 0x00, 0x32, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0xff, 0x01, 0x00, 0x00, 0x91, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x6e, 0x11, 0xc2, 0x45, 0x19, 0x7c, 0x68, 0x45, 0xf8, 0x4f, 0xa4, 0x26, 0xa2, 0x39, 0xce, 0xf1, 0x38, 0x8d, 0x83, 0x35, 0xee, 0x45, 0x74, 0x08, 0x83, 0x08, 0x44, 0x15, 0xf7, 0xd4, 0x38, 0x13};

    Frame::Ptr frame(new Frame(Frame::Context(128, 4096, 4096 - 128, 0, 16, 0)));
    auto [serverconfig, serverfactory, server] = MakeServer(std::move(frame), pvt_key_txt, cert_txt);

    server->start_handshake();

    server->write_ciphertext_unbuffered(clienthello, sizeof(clienthello));

    server->read_cleartext_ready();

    uint8_t cleartext[1024];

    auto ctsize = server->read_cleartext(cleartext, sizeof(cleartext));
    std::cout << ctsize << std::endl;

    EXPECT_TRUE(server->read_ciphertext_ready());
    auto buf = server->read_ciphertext();
    ASSERT_TRUE(buf->length() > 1);
}

#ifdef USE_OPENSSL
/*
   Two MD5 chains, both backdated so that the digest is the only thing wrong with them.
   md5_cert_txt is faulted at depth 0, for its own signature; a trust anchor's signature
   is exempt from the check, so md5_ca_txt is not what fails. md5_inter_txt is faulted at
   depth 1, which is the case Error::SSL_CA_MD_TOO_WEAK is named for and the only one
   verify_callback_client cannot override.

     openssl genrsa -out <name>.key 2048
     openssl req -x509 -new -key md5ca.key -out md5ca.crt -subj "/CN=md5ca" -md5 \
         -not_before 20240101000000Z -not_after 21240101000000Z \
         -addext "basicConstraints=critical,CA:TRUE" \
         -addext "keyUsage=critical,keyCertSign,cRLSign"
     openssl req -new -key md5server.key -out md5server.csr -subj "/CN=md5server"
     openssl x509 -req -in md5server.csr -CA md5ca.crt -CAkey md5ca.key -set_serial 2 \
         -out md5server.crt -md5 -extfile leaf.cnf \
         -not_before 20240101000000Z -not_after 21240101000000Z

   and the same again for the three-certificate chain: a -sha256 root, an intermediate
   signed by it with -md5 and CA:TRUE, then a -sha256 leaf signed by the intermediate.
   leaf.cnf holds basicConstraints=critical,CA:FALSE, extendedKeyUsage=serverAuth and
   keyUsage=digitalSignature,keyEncipherment.
*/
const std::string md5_ca_txt = R"(-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUFdgjzMDakSh82fXObr9mHLTlLj4wDQYJKoZIhvcNAQEE
BQAwEDEOMAwGA1UEAwwFbWQ1Y2EwIBcNMjQwMTAxMDAwMDAwWhgPMjEyNDAxMDEw
MDAwMDBaMBAxDjAMBgNVBAMMBW1kNWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAqe2VN+KCieIX0O9Gx7eXw3L5Lronnz/LwApgUq+iSC/oXmanSQGx
xNrk5nR+2dVHloLaA6ZovOsD6eef5j+MyFIbMJ4RaajENdaBBF8N6qbofQUfa4+d
/MqGvJcpR+M2vtufHG2F9++Svwpmw6t/KagPH5uqa9vp9rGOf+P2ZSi1EzTCXA9/
4QjabKfVqbGRtL3txQOQE1lZ/QtSeJ4RpJ6/Ny23IbUI5Pb+JiQOPAO2vOgNGv9G
AistzB7N4a6/TmEnyx59o8zxMHz1D0OJaSZB4xiuaJ1D+Vq6PUS5JNadlHpbmj4e
JyN2tIIrzDYHAz4VpveBDZOQcaD1sHhbvQIDAQABo2MwYTAdBgNVHQ4EFgQUlcIe
yOykpnhe4W9sIP7t+uymZnEwHwYDVR0jBBgwFoAUlcIeyOykpnhe4W9sIP7t+uym
ZnEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEE
BQADggEBAARuLan28teoCXURfRzCwqMTw1AsseHutopeQdYsCm9KW/+mmHzYEw/3
xzTOlikvxaE71YalkTOBwyTuCC9tMZkeWzDpEPFkwSG2Mm/73od7J9T9ryNeFGxu
xZRNaygdy6U/rMrvBuK5DP5UmqRv5UaH7Aa42E0wFW6qIq/a5Q3ixsrZDTJDXSKq
ZlCBDJYDqmJ3HrNVHRPdG11+PKWuB4tq95BDP1TIGAPd9kcP7hNqNQ5I0K9uNMtJ
Z6x/6R2h7Yl9ImK6baq2+rpA9mEvXrLb6ob/k5TpNnixrWNwiTe09n/4m+PT8F1X
q9nmlYbt88kZe5rS5lciedfyp2ZWJ0s=
-----END CERTIFICATE-----)";

const std::string md5_cert_txt = R"(-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIBAjANBgkqhkiG9w0BAQQFADAQMQ4wDAYDVQQDDAVtZDVj
YTAgFw0yNDAxMDEwMDAwMDBaGA8yMTI0MDEwMTAwMDAwMFowFDESMBAGA1UEAwwJ
bWQ1c2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxHg1Myzy
C6W2NfQzDNPcJuj/QMftmrW3InrgyScvE1ahpe1ugMuv9nbzQb4hzK6RXb9B7MJD
tJ+7H0Gbc4tvWYMSSwRiVQrLOIxiYbQkSh+XIO/qgjoKZfZwsi+UH+sBfZl9VLmy
Iadp072vRB37c0o/WnW9wccMrdmxACLACeAmpWsILgRXksGXJoKVCfvNnAxHburu
6fas/syVyTVB2I7WKoiKFiISKPBJFA4iTZDRLf/8ZqJvwSc1FaHNZKH62A+vR9Ov
0w5pmLYyWwk/lGneH0GjqkOtooC+zuPf2g8BCPrpMSBiuDoQtVc1w46PZPlN67OH
m/RN9mo7ooCPlQIDAQABo3IwcDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMAsGA1UdDwQEAwIFoDAdBgNVHQ4EFgQU812/OqWLqBHNE3zzj5FgxM/N
5gUwHwYDVR0jBBgwFoAUlcIeyOykpnhe4W9sIP7t+uymZnEwDQYJKoZIhvcNAQEE
BQADggEBAHFaytwwf1WChoiPZVagEDr6FjW0ZtHvZmz3sFjWVdRcDvFI2d2Nebgs
HnYzzUFTkqKoPpC+r/KkmxZexVL+fqfY70tGYmAQaXsAknJ0GmTDZbSwtQGo4yeu
yAIL9PL1SVBneJwz8sT6eOLFlq3mPoP5OiwxR5/MEcVxdhCgupPgHh+jSAxuWcvk
jp9H0rW7hId5GRBAN5XD74wZDvjsubhqcqesXWCTzqZeaEARporE9Ofk7VhYBnIb
yjfAUvjqxgIYDrUIi6WbYqSe59/J3r1rWRfll1JNstZTQfiYtm9yOVjO72Bvn4Ex
n7lu7wb6vqHyoYYISX1y88KvXhkfvkQ=
-----END CERTIFICATE-----)";

const std::string md5_pvt_key_txt = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEeDUzLPILpbY1
9DMM09wm6P9Ax+2atbcieuDJJy8TVqGl7W6Ay6/2dvNBviHMrpFdv0HswkO0n7sf
QZtzi29ZgxJLBGJVCss4jGJhtCRKH5cg7+qCOgpl9nCyL5Qf6wF9mX1UubIhp2nT
va9EHftzSj9adb3Bxwyt2bEAIsAJ4CalawguBFeSwZcmgpUJ+82cDEdu6u7p9qz+
zJXJNUHYjtYqiIoWIhIo8EkUDiJNkNEt//xmom/BJzUVoc1kofrYD69H06/TDmmY
tjJbCT+Uad4fQaOqQ62igL7O49/aDwEI+ukxIGK4OhC1VzXDjo9k+U3rs4eb9E32
ajuigI+VAgMBAAECggEAUHcPCtOYmk6XLsfB9Ln8S29Xw1dep+NOiu+aiqfirt/n
OobgoB1MBvw2qrFNNIA2hxeiz23MvvhAcg+ztAHia92zq0ezYjMWgiV00aEuz7Da
e6HnAMj2o0XoaAH2f5AHP0KSwxV+sCvZut/QHWzOJCy/f7QDMI7uUXF7/Zs93YzZ
HV7f65XBULSgbFNlonPT05dZaATxBmboVx3xd0eZAueaRZACyTUg+eM8+h+YKdr9
4/j3lExd6bs3G31G6aEVza9gbyTGzBKmczjVvYWqeB/LSK5uAdZDuhpOUSRJ/iZ8
Z/xeZ3/o+GL7d5c3acH7J17HAMvFc8FpcDwZISvcLQKBgQDuOityfRMgJAl8ZB/q
L5wp62jKAv40MwHe1M9ZAH1g7Vram1meDIvFu8U+JkyHeTpoF76gMqDZ6xdwP6Kp
/Q6shjDQY/eJv3Xb6jUMm9DqouYZ9j9RxWbuTxoLVVkXfDYN6Ey7JYfqA47ePeCU
y/BVXwpTtsbZs4C0J5Gg3JnFwwKBgQDTIIVg4um/36ofAQfIlVN+zc2W0Rs3Jip3
co73lheCgqVABNsouTHxEK31LfBukgo1BXEZsdFcZkd18+6ANPCoA5fo0FWaCWVZ
sXLq6lOK9QWlYx/rDnjzF7bZ+Vc/3n8IcwfUfPAgpr6FlPAP4+25SkpdEYrBAcQK
G41jILqHxwKBgFSFZuzT23lHz+XGUFxyT+G/mAo0TaSPhFZfAsH9Hn7JN7bf70fY
A69AE5cdV4GpTUOpSQTlcZRfiI1WxouxMQedBKyrCyRgPZys1+2FSvY0nZcQex6z
/vUGM6NZwKZId5Uvmim8AyDP6lyHb6rbQIXJloxlCOAsg7lnYI/GNPipAoGANuJ0
afxzQcMWSZsN9/IB06wSrwtLJOoSDh1E1044bGAkL2FTy+Fg/0cTwfIgV841QxVY
EpLsVzXri9lO/htFGJhejFJkfnfE1i1QL4udDjmmLxl2ubd4b9GRYlb0fJENuxeU
SIP2NLbEPpu6UJczPID4lfsyc/xOh0YkWkmu1A8CgYEAgWmgUIZI/E+zzhESQRsv
a6G7WRSYgmca+isPeFEtpPNTasViv7wlY0k8/V07abWU0/osZn0EpZNwVh+IXfe3
5VBQ/N0lzX6sD0e7uT04LlZ47zjtwSQ4XCGpyhHj0y+wMUE464t+P4m6f4gEBmQv
hzlR1d2OIMVBBFr2PXFfRpg=
-----END PRIVATE KEY-----)";

const std::string sha_root_txt = R"(-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIUN4M6TCeUnL+oFqFKjbYgkz6xFG8wDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKc2hhMjU2cm9vdDAgFw0yNDAxMDEwMDAwMDBaGA8yMTI0
MDEwMTAwMDAwMFowFTETMBEGA1UEAwwKc2hhMjU2cm9vdDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAKTPADsYqSGpRrlpKI8Y5/aRufOh4jmKPva/w/Mf
1Yi4DY2I6wZUkS0DsQtVMNSnMmi1I8bSA7KP99y0eAiiAZpqsgH8t8DA4jMXFP8n
bvZjfVsvWD78nzUOCSt8cG6Ft/NrRXm1s+8/VLXUTTxIf3+tP4L/nHHZnkSYPv5j
73JeUcMOTCzB4MNIGwjAKABqBdPmKAcwTyIzmQHl0VR+HqX4Ff/TEV82mv9N48rM
KnuJCIipYECrY3xa+Xq0Jm2JfRggryfuufUxMWTP0JWbA+r5cPPEOoH/E45xqdSh
DFyQEbIsBkN0GQK8ngjtYA/EhMLSRFUXdRryIvKg4atbWm8CAwEAAaNjMGEwHQYD
VR0OBBYEFE28QA3Jc3TIH1nj2JvtSZYxfsFBMB8GA1UdIwQYMBaAFE28QA3Jc3TI
H1nj2JvtSZYxfsFBMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0G
CSqGSIb3DQEBCwUAA4IBAQCJ1CqNJsjtOb1oi6oN+mFGJNW9xJr3tSfBOrPm684F
yPGFBF5YZHygz6BeGB+OJEURxu9i07YbAa31p31rBwTA4b1kgsmlJkOzc0Ss7rf8
b3vQxgt7ICv9MW5E6BmRd//u94rfur48dvdMQwJYiFH5CuDi+dxQIbESyBPmPJNe
3daVVu7GeuJ+Ia7+4dI//KV27/HTUy6GmpyO58UQdjUi8Uxy40gwb36iJynmmoID
xLYlMSpVUf626bsdh4zLJrR/DpGKeewGftkNJZUsgdDoM7nQ0LZpjtpct/SdjS84
C40U/jWjqusYt/y58RYgSZT/2ULvuUVxBacAIMofKOXu
-----END CERTIFICATE-----)";

const std::string md5_inter_txt = R"(-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIBAzANBgkqhkiG9w0BAQQFADAVMRMwEQYDVQQDDApzaGEy
NTZyb290MCAXDTI0MDEwMTAwMDAwMFoYDzIxMjQwMTAxMDAwMDAwWjAaMRgwFgYD
VQQDDA9tZDVpbnRlcm1lZGlhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDMd4KF+sIKDrXE3TFemrKNo5Ugla9LrG5BM59vLLLU2ICUJv23nc0UG99S
8JWm5thxbXWsbqX/oT9As3Lvo32wP17RnmdVMyJYLffYJmMT7kC6sGh4wkhLJKvg
3PwEjYV7zzpdcMOkq880oSwfwKomPSFc/9RcUipSfYSYPtXa2yWMeb3AuiMvuZC7
6fH12o7+Kn9TV7oayqHRMSaUlGTLVNkiOziOO7l3nRLbhiKfSDNravhH1Nn2u18T
MQW8IwW1WoW8CZQXhJw6lQEcsDIZrkHtAogFfBMmc7he5DXihqW9GbGMvqqFQdPD
CqUElaiEq/CuiEqfJJ7Kfu1a2tWBAgMBAAGjYzBhMA8GA1UdEwEB/wQFMAMBAf8w
DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTEeg4BdrQScuBoMq4kkJghQGd5rTAf
BgNVHSMEGDAWgBRNvEANyXN0yB9Z49ib7UmWMX7BQTANBgkqhkiG9w0BAQQFAAOC
AQEAMMHXpdFHQbXsoy5mfogxxXP8omNPTCmEtgkAY9KcXgEdRDxfV9LNaRMlWyWn
nmAGFEiLmV5DLKaqXX6AbvE8iEVGiCUY8HIimW0m5miMW5DirLsbYyInwNwbDTQl
QlHpz7At3Tzaoy6q8C7JEEqVho6dCit8/AwdyubdH/69o6m9qp2i4PDmnmyr6290
MJNRj51X+fPvD26yaCFpGdVd+c/Yy15+RwNQbOpEjQ/lnnQQSjfnuLQ9Ydqf+Y86
y7dLQNe6qtepmYuQ2nfplHageQOWAxnrmK0AejsjMl3M8Q/pp+wKQuVbFnu8NGcU
38qBjYcVD8RYpGdqpikHlUEjlQ==
-----END CERTIFICATE-----)";

const std::string sha_leaf_txt = R"(-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIBBDANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9tZDVp
bnRlcm1lZGlhdGUwIBcNMjQwMTAxMDAwMDAwWhgPMjEyNDAxMDEwMDAwMDBaMBIx
EDAOBgNVBAMMB3NoYWxlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDCaYfd0GCvy7Bw8Kaaiu+fHBvkHGvVbRokWFQ1Joygf2VVtmAD1zCgChbHDOgQ
UAu5I0YNWdy0QJc7cwrS7Cp1NVyVikeP7tx9qqs9upLOK3kV5n9DmgfPbEdIymOt
k01pN2iZ50ouS3bp/l/RtvSigG+ciC7wyIUHoO78C1BqqDfRZiO90Ps4zEd4+E5G
n0K49U7kKDGBFSRkeNjGlONz8XjTWTJLdkmqgjzFqRulnYiuz2SPjJaIpgm4iIuD
AuPlYhUwlSoy0dKm6e5Ok1CY/NZ8zmcEMJhh5w3bWes1TQVUngEYXi1x3kMKQEML
ag0eZ9u1dgRDW3DMz4tg58N3AgMBAAGjcjBwMAwGA1UdEwEB/wQCMAAwEwYDVR0l
BAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgWgMB0GA1UdDgQWBBSqJIuwADe2Ub2U
zZWYdYoTQ4ZfdjAfBgNVHSMEGDAWgBTEeg4BdrQScuBoMq4kkJghQGd5rTANBgkq
hkiG9w0BAQsFAAOCAQEAl9X+LYDZ5Y7XUzrDhPyld4S2fWGurIVRam/ZT1kjkc+w
phlao7B/Iz80AuE2MYXez2tPfle4xE5pX19/s6lecnNZVwKf/yrwmOPkFNG+Wxkh
3sQqFAM8wLM2xQfx/MxwRHC/Y5wuPMD0k6jxOiIo2qxCKRRhxod3gMBBs2lf4CSp
Ap+iGKtu5MG/4jmY4dcY3uOKo00Z3mp/t+p5dWOgbgTpb1td1AhNmuQ9+/k5a3/E
oSzXWpUus5sQ1Pl7zKOPVfsIgYVJOTHcPoFUHe5wW4DJ+T5z/JRcSr5aPcNnbnCT
gWWDapjVtE1aQ+zPi4zuX7fbuCUp+/z12syW8Ga23w==
-----END CERTIFICATE-----)";

const std::string sha_leaf_pvt_key_txt = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDCaYfd0GCvy7Bw
8Kaaiu+fHBvkHGvVbRokWFQ1Joygf2VVtmAD1zCgChbHDOgQUAu5I0YNWdy0QJc7
cwrS7Cp1NVyVikeP7tx9qqs9upLOK3kV5n9DmgfPbEdIymOtk01pN2iZ50ouS3bp
/l/RtvSigG+ciC7wyIUHoO78C1BqqDfRZiO90Ps4zEd4+E5Gn0K49U7kKDGBFSRk
eNjGlONz8XjTWTJLdkmqgjzFqRulnYiuz2SPjJaIpgm4iIuDAuPlYhUwlSoy0dKm
6e5Ok1CY/NZ8zmcEMJhh5w3bWes1TQVUngEYXi1x3kMKQEMLag0eZ9u1dgRDW3DM
z4tg58N3AgMBAAECggEAIz0LonoNvG+YOLB2ElcSne1zZMJ+DT5sWaAlC0lEfib5
UDLxbmDH8IpDnKrLOYG4zkMFhJAAQC/g+aadlKO4Amy8rmJVHFK4ZpLT3Sl/SJ16
oiyYbsFxnvhKZ3g/3wtvIZ4oeJUCzidhk4JHDfUynG3ZTS8mCwDdlAdoqgjG973a
/jf16lgrvEhtQtX/J1SJbgjmj+2D/jlejV6/Oxn6AReVRA7y6P6i7Y8UakLpkVQy
BOYO7kUu/M8kPQbYG7ISvQSPG1P6UBdCDo7hh3nk+b7dY2zKm3toAcNz4/B2gq5Z
4IDdWuR7TmZ5f/fdDcg060kmasn84yRYQc8TjaGOiQKBgQDqlb/atceyJM4SjMYi
iVTzl7xz/gRTD5HlJb72WBQ09E8fdqqj2M/ul19pK1j2J8ICET/Bh7DAp0shlOlZ
YYakoq9c+9pnZBFAaDSMP5iuHPsfthdQpPFzIc18vfV3Pf1VVBHoeGrbKAzRTIX0
2Zqj6d7CpxVyuhuHGO+i1i2YYwKBgQDUKPHRPxMh46bDmo5+dxtE7IuTOasv440D
qcL8ypWE0XMEIxKHz7yehibQYmdWr8CaAk8CmcaPN0ZTLXJ5sFcxNSLo057cUnUZ
Bs65hlxFWa4StHq+srvIqkqfoame71cs05kjKxW7yAB4TfVVCKSTIdP+JAbhuSbX
RgYcHm7S3QKBgQCQf3ezT//XUuaA9KfjhDaI6fGSfWjKhS+4N9z+P1kLGWZXmjAY
Rygl7qY90Q62ad0OivN70Ypl0WbtI53tia53YSKmIxjwUOpzgvzDWzVAIufpK7AG
4+M6qRq7eQNn1Q5kbimtyecAYhYrInjtTtD7oMavnl4O0ma8e/a4ljd1wwKBgClZ
dY/nsC3ptaXn6J/DTQBI7gcatT+XJPOy0Xr9bNi/DaCfyUvI9CUdVlFE7Ikbpfke
PBHwsJ9XEZDCic4nzUac6ZnhLNQaChJ/nijQhAlMKj4hCM9D/I9miTbFhk6grSfi
cbVF/21i1Jyd7RPOpGy8qhmdIe46bNSGJEi0sbrNAoGAfij7gEWo/XBrHX9S3cIq
HmLEWQtmrTcGPsYWCykTDgm6/86ySDyrf1C7busGhwkoaBLiN+7mD3tDrmL2bUFY
edEkCHXeoRhlX1o2FrJIPrD8+lKmeF5aAEdLannMVvIoGT9mtQF1w5yk5aTdgPRm
ZoBMXW/DMuCB88kWJPCz2xI=
-----END PRIVATE KEY-----)";

/**
 * @brief Handshakes against a chain carrying a weak signature digest and expects it to
 *        be rejected as Error::SSL_CA_MD_TOO_WEAK, naming the certificate at fault
 * @param server_cert  the server's own certificate
 * @param server_key   the private key for @p server_cert
 * @param client_ca    the CA the client trusts
 * @param depth        the depth the rejection is expected at
 *
 * The server is handed cert_txt as its own CA so that the client's certificate verifies
 * and the weak digest is the only thing either peer can object to.
 */
static inline void ExpectWeakDigestRejected(const std::string &server_cert,
                                            const std::string &server_key,
                                            const std::string &client_ca,
                                            const int depth)
{
    Frame::Ptr frame(new Frame(Frame::Context(128, 4096, 4096 - 128, 0, 16, 0)));

    SSLLib::SSLAPI::Config::Ptr serverconfig, clientconfig;
    SSLFactoryAPI::Ptr serverfactory, clientfactory;
    SSLAPI::Ptr server, client;

    try
    {
        std::tie(serverconfig, serverfactory, server) = MakeServer(frame, server_key, server_cert, cert_txt);
        std::tie(clientconfig, clientfactory, client) = MakeClient(std::move(frame), pvt_key_txt, cert_txt, client_ca);
    }
    catch (const ExceptionCode &e)
    {
        // An OpenSSL predating openssl/openssl#31271 refuses the chain as it is loaded,
        // which leaves everything below unexercised
        EXPECT_EQ(e.code(), Error::SSL_CA_MD_TOO_WEAK) << e.what();
        GTEST_SKIP() << "chain refused before the handshake: " << e.what();
    }

    try
    {
        client->start_handshake();

        for (auto i = 0U; i < ITER; ++i)
            xfer(*client, *server);
    }
    catch (const ExceptionCode &e)
    {
        EXPECT_EQ(e.code(), Error::SSL_CA_MD_TOO_WEAK) << e.what();
        // The reason reaches the event through add_context(), except on an OpenSSL whose
        // own error stack named the digest, where the code needed no refining
        const std::string text = e.what();
        if (text.find("ca md too weak") == std::string::npos)
        {
            // not an OpenSSL that names the digest itself, so add_context() must
            EXPECT_NE(text.find("CA signature digest algorithm too weak at depth " + std::to_string(depth)),
                      std::string::npos)
                << e.what();
        }
        // OpenSSL has queued a bad_certificate alert, and ProtoStackBase only sends it
        // out for a failure flush_pending_ciphertext() accepts
        EXPECT_TRUE(e.flush_pending_ciphertext());
        EXPECT_TRUE(client->read_ciphertext_ready()) << "the rejecting peer queued no alert";
        return;
    }
    FAIL() << "MD5-signed certificate chain was accepted";
}

/** @brief A leaf signed with MD5 by its CA, faulted at depth 0 */
TEST(sslctx_ut, WeakDigestLeafHandshakeFail)
{
    ExpectWeakDigestRejected(md5_cert_txt, md5_pvt_key_txt, md5_ca_txt, 0);
}

/**
 * @brief An MD5-signed intermediate under a strong root, faulted at depth 1
 *
 * The client trusts the intermediate rather than the server sending it, so the server
 * never handles a weak certificate: an OpenSSL that still checks the digest as a chain
 * is sent rejects its own chain before the client can verify anything, which is how an
 * earlier revision of this test failed on every CI distro.
 *
 * sha_root_txt has to stay in the bundle for that to work. It is what keeps the
 * intermediate a mid-chain certificate at depth 1; on its own the intermediate would be
 * the trust anchor, and an anchor's own signature is exempt from the check.
 */
TEST(sslctx_ut, WeakDigestIntermediateHandshakeFail)
{
    ExpectWeakDigestRejected(sha_leaf_txt, sha_leaf_pvt_key_txt, sha_root_txt + "\n" + md5_inter_txt, 1);
}
#endif
