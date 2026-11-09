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

// Tests for ProtoContext::ProbeWrap -- wrapping a probe request and
// unwrapping the matching probe reply with each control-channel protection mode
// (tls-auth, tls-crypt, tls-crypt-v2, plaintext), built standalone from a
// ProtoConfig without an established session. Each test wraps as the client, then
// plays the server with the low-level static helpers (ProtoContext::build_* /
// unwrap_*), verifying the framing round-trips and the OOB payload survives.

#include "test_common.hpp"

#include <gtest/gtest.h>

#include <openvpn/common/file.hpp>
#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/ssl/proto.hpp>
#include <openvpn/ssl/oob_probe.hpp>
#include <openvpn/crypto/ovpnhmac.hpp>
#include <openvpn/crypto/tls_crypt.hpp>
#include <openvpn/crypto/tls_crypt_v2.hpp>

using namespace openvpn;

namespace {

// key/cert material lives next to the unit tests, in ../ssl
#define OOB_KEYDIR UNITTEST_SOURCE_DIR "../ssl/"

enum class WrapMode
{
    PLAIN,
    AUTH,
    CRYPT,
    CRYPT_V2,
};

// Build a minimal client ProtoConfig carrying just enough to wrap a control
// packet in the requested mode. tls-auth uses bidirectional key-direction so the
// same HMAC key wraps and unwraps within a single config; tls-crypt derives its
// direction from the client/server role, matched by the server side below.
ProtoContext::ProtoConfig::Ptr make_config(WrapMode m, Frame::Ptr frame, StrongRandomAPI::Ptr rng, Time &time)
{
    auto cp = ProtoContext::ProtoConfig::Ptr(new ProtoContext::ProtoConfig());
    cp->frame = frame;
    cp->now = &time;
    cp->rng = rng;
    cp->prng = rng;

    const std::string tls_auth_key = read_text(OOB_KEYDIR "tls-auth.key");

    switch (m)
    {
    case WrapMode::AUTH:
        cp->tls_auth_factory.reset(new CryptoOvpnHMACFactory<SSLLib::CryptoAPI>());
        cp->tls_auth_key.parse(tls_auth_key);
        cp->set_tls_auth_digest(CryptoAlgs::lookup("SHA256"));
        cp->key_direction = -1; // bidirectional
        break;
    case WrapMode::CRYPT:
    case WrapMode::CRYPT_V2:
        {
            // tls-crypt needs an SSL library context (for its cipher), obtained from
            // an ssl_factory -- build one exactly as the proto tests do
            auto cc = SSLLib::SSLAPI::Config::Ptr(new SSLLib::SSLAPI::Config());
            cc->set_mode(Mode(Mode::CLIENT));
            cc->set_frame(frame);
            cc->set_rng(rng);
            cc->load_ca(read_text(OOB_KEYDIR "ca.crt"), true);
            cc->load_cert(read_text(OOB_KEYDIR "client.crt"));
            cc->load_private_key(read_text(OOB_KEYDIR "client.key"));
            cp->ssl_factory = cc->new_factory();

            cp->tls_crypt_factory.reset(new CryptoTLSCryptFactory<SSLLib::CryptoAPI>());
            cp->set_tls_crypt_algs();
            if (m == WrapMode::CRYPT)
            {
                cp->tls_crypt_key.parse(tls_auth_key);
                cp->tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V1;
            }
            else
            {
                TLSCryptV2ClientKey k(cp->tls_crypt_context);
                k.parse(read_text(OOB_KEYDIR "tls-crypt-v2-client.key"));
                k.extract_key(cp->tls_crypt_key);
                k.extract_wkc(cp->wkc);
                cp->tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V2;
            }
            break;
        }
    case WrapMode::PLAIN:
        break;
    }
    return cp;
}

// Stateless server end: unwraps a client probe and wraps a reply, using the
// control-channel protection built with the *server* role (so the encrypt/decrypt
// slices are the mirror of the client's). For tls-crypt-v2 the server key is the
// Kc the client sent wrapped as WKc; here both sides share it via the config.
class ServerSim
{
  public:
    ServerSim(const ProtoContext::ProtoConfig::Ptr &cp, WrapMode m, const SessionStats::Ptr &stats)
        : config(cp), mode(m)
    {
        pid_recv.init("OOB-SRV", 0, stats);
        psid_self.randomize(*config->rng);

        switch (mode)
        {
        case WrapMode::AUTH:
            hmac_size = config->tls_auth_context->size();
            ProtoContext::build_tls_auth(*config, ta_send, ta_recv);
            break;
        case WrapMode::CRYPT:
        case WrapMode::CRYPT_V2:
            hmac_size = config->tls_crypt_context->digest_size();
            ProtoContext::build_tls_crypt(*config, true, config->tls_crypt_key, tc_send, tc_recv);
            break;
        case WrapMode::PLAIN:
            break;
        }
    }

    ProtoContext::UnwrapStatus unwrap(BufferAllocated &buf,
                                      BufferAllocated &work,
                                      ProtoSessionID &src,
                                      PacketIDControl &pid)
    {
        switch (mode)
        {
        case WrapMode::AUTH:
            return ProtoContext::unwrap_tls_auth(buf, hmac_size, *ta_recv, pid_recv, src, pid);
        case WrapMode::CRYPT:
        case WrapMode::CRYPT_V2:
            return ProtoContext::unwrap_tls_crypt(buf, work, *config->frame, hmac_size, *tc_recv, pid_recv, src, pid);
        case WrapMode::PLAIN:
            buf.advance(1);
            src.read(buf);
            return ProtoContext::UnwrapStatus::OK;
        }
        return ProtoContext::UnwrapStatus::DROP;
    }

    // wrap a server->client reply; plain tls-crypt for v2 (the reply carries no WKc)
    void wrap_reply(BufferAllocated &buf, BufferAllocated &work)
    {
        const PacketIDControl::time_t now_secs = config->now->seconds_since_epoch();
        switch (mode)
        {
        case WrapMode::AUTH:
            ProtoContext::wrap_tls_auth(ProtoContext::CONTROL_V2, buf, pid_send, now_secs, hmac_size, psid_self, 0, *ta_send);
            break;
        case WrapMode::CRYPT:
        case WrapMode::CRYPT_V2:
            ProtoContext::wrap_tls_crypt(ProtoContext::CONTROL_V2, buf, work, *config->frame, pid_send, now_secs, hmac_size, psid_self, 0, *tc_send, nullptr);
            break;
        case WrapMode::PLAIN:
            ProtoContext::wrap_tls_plain(ProtoContext::CONTROL_V2, buf, psid_self, 0);
            break;
        }
    }

    ProtoSessionID psid_self;

  private:
    ProtoContext::ProtoConfig::Ptr config;
    WrapMode mode;
    size_t hmac_size = 0;
    OvpnHMACInstance::Ptr ta_send, ta_recv;
    TLSCryptInstance::Ptr tc_send, tc_recv;
    PacketIDControlSend pid_send;
    PacketIDControlReceive pid_recv;
};

BufferAllocated make_msg_buffer()
{
    BufferAllocated buf;
    buf.reset(512 /*headroom*/, 2048 /*capacity*/, BufAllocFlags::NO_FLAGS);
    return buf;
}

// client probe request -> server unwrap -> server probe reply -> client unwrap
void run_roundtrip(WrapMode mode) // NOLINT(readability-function-cognitive-complexity) -- a linear round-trip, the count is gtest macro expansion
{
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    // Use the SSL library's own RNG: mbedTLS requires an MbedTLSRandom for the
    // SSL context built below (tls-crypt), and a real RNG is fine here since the
    // tests assert round-trip correctness, not specific random bytes.
    StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());
    Time time = Time::now();
    auto cp = make_config(mode, frame, rng, time);
    SessionStats::Ptr stats(new SessionStats());

    ProtoContext::ProbeWrap client(cp, stats);
    ServerSim server(cp, mode, stats);

    // ---- client wraps a probe request ----
    const oob::ProbeRequest req{
        .request_id = 0x0123456789abcdefULL,
        .timestamp = 0x1122334455667788ULL,
        .flags = 0,
    };

    BufferAllocated probe = make_msg_buffer();
    ASSERT_TRUE(req.write(probe));
    BufferAllocated cwork;
    client.wrap(probe, cwork);

    // ---- server unwraps it ----
    BufferAllocated swork;
    ProtoSessionID src;
    PacketIDControl pid;
    ASSERT_EQ(server.unwrap(probe, swork, src, pid), ProtoContext::UnwrapStatus::OK);
    EXPECT_TRUE(src.match(client.self_psid()));

    const auto got_req_opt = oob::probe_request_find(probe);
    ASSERT_TRUE(got_req_opt);
    const auto &got_req = *got_req_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(got_req.request_id, req.request_id);
    EXPECT_EQ(got_req.timestamp, req.timestamp);
    EXPECT_EQ(got_req.flags, req.flags);

    // ---- server wraps a probe reply ----
    const oob::ProbeReply reply{
        .request_id = req.request_id,
        .priority = 3,
        .weight = 7,
        .max_latency_diff = 0,
        .connect_lifetime = 60,
        .flags = 0,
    };

    BufferAllocated rbuf = make_msg_buffer();
    ASSERT_TRUE(reply.write(rbuf));
    BufferAllocated rwork;
    server.wrap_reply(rbuf, rwork);

    // ---- client unwraps the reply ----
    BufferAllocated cwork2;
    ProtoSessionID rsrc;
    PacketIDControl rpid;
    ASSERT_EQ(client.unwrap(rbuf, cwork2, rsrc, rpid), ProtoContext::UnwrapStatus::OK);
    EXPECT_TRUE(rsrc.match(server.psid_self));

    const auto got_reply_opt = oob::probe_reply_find(rbuf);
    ASSERT_TRUE(got_reply_opt);
    const auto &got_reply = *got_reply_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(got_reply.request_id, reply.request_id);
    EXPECT_EQ(got_reply.priority, reply.priority);
    EXPECT_EQ(got_reply.weight, reply.weight);
    EXPECT_EQ(got_reply.connect_lifetime, reply.connect_lifetime);
}

} // namespace

TEST(OobProbeWrap, plaintext_roundtrip)
{
    run_roundtrip(WrapMode::PLAIN);
}

TEST(OobProbeWrap, tls_auth_roundtrip)
{
    run_roundtrip(WrapMode::AUTH);
}

TEST(OobProbeWrap, tls_crypt_roundtrip)
{
    run_roundtrip(WrapMode::CRYPT);
}

// tls-crypt-v2: the probe must use the WKc-bearing opcode and carry the wrapped
// client key as a trailer; stripping it, the server (holding the same Kc) unwraps
// the probe body. The reply direction is covered by tls_crypt_roundtrip.
TEST(OobProbeWrap, tls_crypt_v2_probe_appends_wkc)
{
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());
    Time time = Time::now();
    auto cp = make_config(WrapMode::CRYPT_V2, frame, rng, time);
    SessionStats::Ptr stats(new SessionStats());

    ASSERT_TRUE(cp->wkc.defined());
    const size_t wkc_size = cp->wkc.size();

    ProtoContext::ProbeWrap client(cp, stats);

    const oob::ProbeRequest req{.timestamp = 0xdeadbeefcafef00dULL, .flags = 0};

    BufferAllocated probe = make_msg_buffer();
    ASSERT_TRUE(req.write(probe));
    BufferAllocated cwork;
    client.wrap(probe, cwork);

    // opcode is CONTROL_WKC_V2 with key-id 0
    const unsigned char expected_op = ProtoContext::op_compose(ProtoContext::CONTROL_WKC_V2, 0);
    ASSERT_GE(probe.size(), wkc_size);
    EXPECT_EQ(probe.c_data()[0], expected_op);

    // the last wkc_size bytes are exactly the wrapped client key
    EXPECT_EQ(std::memcmp(probe.c_data() + probe.size() - wkc_size, cp->wkc.c_data(), wkc_size), 0);

    // strip the WKc trailer; the server (same Kc) unwraps the remaining probe
    BufferAllocated stripped;
    stripped.reset(0, probe.size(), BufAllocFlags::NO_FLAGS);
    stripped.write(probe.c_data(), probe.size() - wkc_size);

    ServerSim server(cp, WrapMode::CRYPT_V2, stats);
    BufferAllocated swork;
    ProtoSessionID src;
    PacketIDControl pid;
    ASSERT_EQ(server.unwrap(stripped, swork, src, pid), ProtoContext::UnwrapStatus::OK);
    EXPECT_TRUE(src.match(client.self_psid()));

    const auto got_req_opt = oob::probe_request_find(stripped);
    ASSERT_TRUE(got_req_opt);
    const auto &got_req = *got_req_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(got_req.timestamp, req.timestamp);
}

namespace {

// A reply too short to hold the fixed [op][psid][pid][hmac] header must be
// dropped, not parsed: ProbeWrap::unwrap() runs in the prober's asio receive
// handler, where the advance()/read() underflow exception would escape into the
// event loop. Feed every wrap mode a range of truncated datagrams.
void run_truncated_reply_is_dropped(WrapMode m)
{
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());
    Time time = Time::now();
    auto cp = make_config(m, frame, rng, time);
    SessionStats::Ptr stats(new SessionStats());

    ProtoContext::ProbeWrap client(cp, stats);

    // 1 byte (opcode only) up to a partial session id -- all below any header size
    const unsigned char junk[ProtoSessionID::SIZE] = {};
    for (size_t len = 1; len <= sizeof(junk); ++len)
    {
        BufferAllocated recv = make_msg_buffer();
        recv.write(junk, len);

        BufferAllocated work;
        ProtoSessionID src;
        PacketIDControl pid;
        EXPECT_EQ(client.unwrap(recv, work, src, pid), ProtoContext::UnwrapStatus::DROP) << "len=" << len;
    }
}

} // namespace

TEST(OobProbeWrap, plaintext_truncated_reply_is_dropped)
{
    run_truncated_reply_is_dropped(WrapMode::PLAIN);
}

TEST(OobProbeWrap, tls_auth_truncated_reply_is_dropped)
{
    run_truncated_reply_is_dropped(WrapMode::AUTH);
}

TEST(OobProbeWrap, tls_crypt_truncated_reply_is_dropped)
{
    run_truncated_reply_is_dropped(WrapMode::CRYPT);
}
