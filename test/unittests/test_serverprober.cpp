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

// Tests for ServerProber: drive it against a loopback fake server that answers a
// probe request with a probe reply, and check the prober reports the responding
// remote with its advertised parameters and a measured round-trip time. Uses the
// plaintext control-channel mode so the fake server needs no key material.

#include "test_common.hpp"

#include <cstdint>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include <openvpn/io/io.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/transport/protocol.hpp>
#include <openvpn/client/remotelist.hpp>
#include <openvpn/client/serverprober.hpp>
#include <openvpn/ssl/oob_probe.hpp>

using namespace openvpn;

namespace {

// Minimal client/server ProtoConfig with no control-channel keys -> plaintext
// wrapping. ProbeWrap only needs frame/now/rng and a stats object.
ProtoContext::ProtoConfig::Ptr make_plain_config(Frame::Ptr frame, StrongRandomAPI::Ptr rng, Time &time)
{
    auto cp = ProtoContext::ProtoConfig::Ptr(new ProtoContext::ProtoConfig());
    cp->frame = frame;
    cp->now = &time;
    cp->rng = rng;
    cp->prng = rng;
    return cp;
}

// A loopback UDP server that answers a single probe request with a probe reply,
// echoing the request_id and advertising fixed parameters. With echo_request_id
// false it answers a different id, as a spoofed reply would.
class FakeProbeServer
{
  public:
    FakeProbeServer(openvpn_io::io_context &io_ctx, const ProtoContext::ProtoConfig::Ptr &cfg, const SessionStats::Ptr &stats, const bool echo_request_id_arg = true) // NOLINT(misc-include-cleaner) -- openvpn_io is the asio indirection used across the tree
        : socket(io_ctx), wrap(cfg, stats), echo_request_id(echo_request_id_arg)
    {
        socket.open(openvpn_io::ip::udp::v4());
        socket.bind(openvpn_io::ip::udp::endpoint(openvpn_io::ip::make_address("127.0.0.1"), 0));
    }

    unsigned short port() const
    {
        return socket.local_endpoint().port();
    }

    void start()
    {
        do_recv();
    }

    void stop()
    {
        openvpn_io::error_code ec;
        socket.close(ec);
    }

    //! flags of the last probe request received, for the caller to assert on
    std::uint32_t last_request_flags = 0;

    static constexpr std::uint16_t REPLY_PRIORITY = 5;
    static constexpr std::uint16_t REPLY_WEIGHT = 9;
    static constexpr std::uint16_t REPLY_CONNECT_LIFETIME = 42;

  private:
    struct RecvCtx
    {
        BufferAllocated buf;
        openvpn_io::ip::udp::endpoint sender;
    };

    void do_recv()
    {
        auto rc = std::make_shared<RecvCtx>();
        rc->buf.reset(0, 1600, BufAllocFlags::NO_FLAGS);
        socket.async_receive_from(rc->buf.mutable_buffer(), rc->sender, [this, rc](const openvpn_io::error_code &error, const size_t n)
                                  {
                                      if (error || !n)
                                      {
                                          return;
                                      }
                                      rc->buf.set_size(n);
                                      respond(rc->buf, rc->sender); });
    }

    void respond(BufferAllocated &buf, const openvpn_io::ip::udp::endpoint &sender)
    {
        BufferAllocated work;
        ProtoSessionID client_psid;
        PacketIDControl pid;
        if (wrap.unwrap(buf, work, client_psid, pid) != ProtoContext::UnwrapStatus::OK)
        {
            return;
        }

        const auto req = oob::probe_request_find(buf);
        if (!req)
        {
            return;
        }
        last_request_flags = req->flags;

        const oob::ProbeReply reply{
            .request_id = echo_request_id ? req->request_id : ~req->request_id,
            .priority = REPLY_PRIORITY,
            .weight = REPLY_WEIGHT,
            .max_latency_diff = 0,
            .connect_lifetime = REPLY_CONNECT_LIFETIME,
            .flags = 0,
        };

        BufferAllocated rbuf;
        rbuf.reset(512, 2048, BufAllocFlags::NO_FLAGS);
        if (!reply.write(rbuf))
        {
            return;
        }
        BufferAllocated rwork;
        wrap.wrap(rbuf, rwork);

        openvpn_io::error_code ec;
        socket.send_to(rbuf.const_buffer(), sender, 0, ec);
    }

    openvpn_io::ip::udp::socket socket;
    ProtoContext::ProbeWrap wrap;
    bool echo_request_id;
};

struct Collector : public ServerProber::NotifyCallback
{
    std::vector<ServerProber::Result> results;
    bool done = false;

    void server_probe_done(std::vector<ServerProber::Result> r) override
    {
        results = std::move(r);
        done = true;
    }
};

} // namespace

TEST(ServerProber, PlaintextProbeRoundtrip)
{
    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x33));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    // fake server on an ephemeral loopback port
    FakeProbeServer server(io_ctx, make_plain_config(frame, rng, time), stats);
    server.start();
    const unsigned short port = server.port();

    // one already-resolved UDP remote pointing at the fake server
    RemoteList::Ptr rl(new RemoteList("127.0.0.1", std::to_string(port), Protocol(Protocol::UDPv4), "test"));
    rl->get_item(0)->set_ip_addr(IP::Addr::from_string("127.0.0.1"));

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr, // no socket_protect
                                                       stats,
                                                       Time::Duration::milliseconds(300));

    Collector cb;
    prober->start(&cb);
    io_ctx.run();

    ASSERT_TRUE(cb.done);
    ASSERT_EQ(cb.results.size(), 1u);
    const ServerProber::Result &r = cb.results[0];
    EXPECT_EQ(r.remote_index, 0u);
    EXPECT_EQ(r.addr.to_string(), "127.0.0.1");
    EXPECT_EQ(r.port, port);
    EXPECT_EQ(r.reply.priority, FakeProbeServer::REPLY_PRIORITY);
    EXPECT_EQ(r.reply.weight, FakeProbeServer::REPLY_WEIGHT);
    EXPECT_EQ(r.reply.connect_lifetime, FakeProbeServer::REPLY_CONNECT_LIFETIME);
    EXPECT_LE(r.rtt, Time::Duration::seconds(2)); // sane, non-garbage latency
    // the prober measures only, so the server is told it need not hold the state
    EXPECT_EQ(server.last_request_flags, oob::request_flag_probe_only);

    server.stop();
}

// A reply that is correctly wrapped and comes from the address we probed, but
// does not echo our request_id, is not an answer to our probe.
TEST(ServerProber, ReplyWithWrongRequestIdIsIgnored)
{
    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x55));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    FakeProbeServer server(io_ctx, make_plain_config(frame, rng, time), stats, false);
    server.start();

    RemoteList::Ptr rl(new RemoteList("127.0.0.1", std::to_string(server.port()), Protocol(Protocol::UDPv4), "test"));
    rl->get_item(0)->set_ip_addr(IP::Addr::from_string("127.0.0.1"));

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr,
                                                       stats,
                                                       Time::Duration::milliseconds(300));

    Collector cb;
    prober->start(&cb);
    io_ctx.run();

    ASSERT_TRUE(cb.done);
    EXPECT_EQ(cb.results.size(), 0u);

    server.stop();
}

// No server listening: the probe window elapses and the prober reports nothing.
TEST(ServerProber, NoReplyTimesOutEmpty)
{
    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x44));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    // 127.0.0.1:1 -- nothing listening
    RemoteList::Ptr rl(new RemoteList("127.0.0.1", "1", Protocol(Protocol::UDPv4), "test"));
    rl->get_item(0)->set_ip_addr(IP::Addr::from_string("127.0.0.1"));

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr,
                                                       stats,
                                                       Time::Duration::milliseconds(200));

    Collector cb;
    prober->start(&cb);
    io_ctx.run();

    ASSERT_TRUE(cb.done);
    EXPECT_EQ(cb.results.size(), 0u);
}

// Nothing resolved -> the callback still fires (immediately), with no results.
TEST(ServerProber, EmptyRemoteListCompletes)
{
    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x55));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    // resolved list intentionally left empty (no set_ip_addr)
    RemoteList::Ptr rl(new RemoteList("127.0.0.1", "1194", Protocol(Protocol::UDPv4), "test"));

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr,
                                                       stats,
                                                       Time::Duration::milliseconds(200));

    Collector cb;
    prober->start(&cb);
    io_ctx.run();

    ASSERT_TRUE(cb.done);
    EXPECT_EQ(cb.results.size(), 0u);
}

namespace {

// A server that answers every probe with a runt datagram, i.e. the malformed
// input a hostile or broken peer can put on the wire.
class FakeRuntServer
{
  public:
    explicit FakeRuntServer(openvpn_io::io_context &io_ctx)
        : socket(io_ctx)
    {
        socket.open(openvpn_io::ip::udp::v4());
        socket.bind(openvpn_io::ip::udp::endpoint(openvpn_io::ip::make_address("127.0.0.1"), 0));
    }

    unsigned short port() const
    {
        return socket.local_endpoint().port();
    }

    void start()
    {
        do_recv();
    }

    void stop()
    {
        openvpn_io::error_code ec;
        socket.close(ec);
    }

  private:
    struct RecvCtx
    {
        BufferAllocated buf;
        openvpn_io::ip::udp::endpoint sender;
    };

    void do_recv()
    {
        auto rc = std::make_shared<RecvCtx>();
        rc->buf.reset(0, 1600, BufAllocFlags::NO_FLAGS);
        socket.async_receive_from(rc->buf.mutable_buffer(), rc->sender, [this, rc](const openvpn_io::error_code &error, const size_t n)
                                  {
                                      if (error || !n)
                                      {
                                          return;
                                      }
                                      // 3 bytes: an opcode and not much else
                                      static const unsigned char runt[3] = {0x60, 0x01, 0x02};
                                      openvpn_io::error_code ec;
                                      socket.send_to(openvpn_io::buffer(runt, sizeof(runt)), rc->sender, 0, ec); });
    }

    openvpn_io::ip::udp::socket socket;
};

} // namespace

// A truncated reply must be dropped without disturbing the probe: the window
// still closes normally and the prober reports no responder. Before the header
// length check this threw out of the asio receive handler.
TEST(ServerProber, TruncatedReplyIsDropped)
{
    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x66));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    FakeRuntServer server(io_ctx);
    server.start();

    RemoteList::Ptr rl(new RemoteList("127.0.0.1", std::to_string(server.port()), Protocol(Protocol::UDPv4), "test"));
    rl->get_item(0)->set_ip_addr(IP::Addr::from_string("127.0.0.1"));

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr,
                                                       stats,
                                                       Time::Duration::milliseconds(300));

    Collector cb;
    prober->start(&cb);
    io_ctx.run(); // must not propagate an exception

    ASSERT_TRUE(cb.done);
    EXPECT_EQ(cb.results.size(), 0u);

    server.stop();
}
