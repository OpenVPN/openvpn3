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
#include <chrono>
#include <map>
#include <set>
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
#include <openvpn/common/options.hpp>
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

// A loopback UDP server that answers probe requests with a probe reply.
//
// What it announces is scriptable, so several of them can stand in for servers
// that differ -- which is the only way to test the ranking over the real wire
// format, the production server having no way to configure what it announces.
// It can also stay silent, standing in for an address that never answers, and
// with echo_request_id false it answers a different id, as a spoof would.
class FakeProbeServer
{
  public:
    static constexpr std::uint16_t REPLY_PRIORITY = 5;
    static constexpr std::uint16_t REPLY_WEIGHT = 9;
    static constexpr std::uint16_t REPLY_CONNECT_LIFETIME = 42;

    //! What this server announces. Defaults reproduce the original fixed reply.
    struct Reply
    {
        std::uint16_t priority = REPLY_PRIORITY;
        std::uint16_t weight = REPLY_WEIGHT;
        std::uint16_t max_latency_diff = 0;
        std::uint16_t connect_lifetime = REPLY_CONNECT_LIFETIME;
        std::uint16_t flags = 0;
    };

    FakeProbeServer(openvpn_io::io_context &io_ctx, const ProtoContext::ProtoConfig::Ptr &cfg, const SessionStats::Ptr &stats, const bool echo_request_id_arg = true, const bool v6_arg = false) // NOLINT(misc-include-cleaner) -- openvpn_io is the asio indirection used across the tree
        : v6(v6_arg), socket(io_ctx), wrap(cfg, stats), echo_request_id(echo_request_id_arg)
    {
        socket.open(v6 ? openvpn_io::ip::udp::v6() : openvpn_io::ip::udp::v4());
        socket.bind(openvpn_io::ip::udp::endpoint(openvpn_io::ip::make_address(address()), 0));
    }

    //! Loopback address this server answers on, in the form a config wants it.
    const char *address() const
    {
        return v6 ? "::1" : "127.0.0.1";
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

    //! What to announce; change before start().
    Reply reply;

    //! Receive but never answer, as an address that is simply not there.
    bool silent = false;

    //! flags of the last probe request received, for the caller to assert on
    std::uint32_t last_request_flags = 0;

    //! How many probe requests arrived, so a test can assert what was sent.
    size_t requests_received = 0;

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
        ++requests_received;
        if (silent)
        {
            return;
        }

        const oob::ProbeReply out{
            .request_id = echo_request_id ? req->request_id : ~req->request_id,
            .priority = reply.priority,
            .weight = reply.weight,
            .max_latency_diff = reply.max_latency_diff,
            .connect_lifetime = reply.connect_lifetime,
            .flags = reply.flags,
        };

        BufferAllocated rbuf;
        rbuf.reset(512, 2048, BufAllocFlags::NO_FLAGS);
        if (!out.write(rbuf))
        {
            return;
        }
        BufferAllocated rwork;
        wrap.wrap(rbuf, rwork);

        openvpn_io::error_code ec;
        socket.send_to(rbuf.const_buffer(), sender, 0, ec);
    }

    // declared before the socket: the constructor body opens it by family
    bool v6;

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

// ---------------------------------------------------------------------------
// Probe timing resolution.
//
// These guard the property the ranking depends on rather than any particular
// number: a probe clock must resolve differences well below the ~15.6 ms
// Windows system tick, because max_latency_diff defaults to 0 and that makes
// the candidate band an exact RTT tie. Measured against Time::now() these
// would fail on Windows, where it reads GetTickCount64.

TEST(ServerProber, ElapsedResolvesBelowTheSystemTick)
{
    const auto start = std::chrono::steady_clock::now();

    // Busy-wait rather than sleep: a sleep is itself quantized to the system
    // tick, which is the very thing under test. 3 ms is comfortably inside one
    // tick, so a tick-granular clock would usually still report 0 here.
    while (std::chrono::steady_clock::now() - start < std::chrono::milliseconds(3))
    {
    }

    const Time::Duration elapsed = ServerProber::elapsed_since(start);
    EXPECT_GT(elapsed.to_binary_ms(), 0u) << "probe clock cannot resolve a 3 ms interval";
    EXPECT_LT(elapsed.to_milliseconds(), 1000u) << "implausible for a 3 ms busy-wait";
}

TEST(ServerProber, ElapsedIsMonotonicAndStartsAtZero)
{
    const auto origin = std::chrono::steady_clock::now();
    const Time::Duration immediate = ServerProber::elapsed_since(origin);
    EXPECT_LT(immediate.to_milliseconds(), 100u);

    Time::Duration prev = immediate;
    for (int i = 0; i < 50; ++i)
    {
        const Time::Duration now = ServerProber::elapsed_since(origin);
        EXPECT_GE(now.to_binary_ms(), prev.to_binary_ms()) << "elapsed went backwards";
        prev = now;
    }
}

// ---------------------------------------------------------------------------
// First-wave target selection.
//
// Pure policy: no sockets, no clock. Builds per-remote endpoint lists directly
// rather than going through RemoteList, so each rule can be stated on its own.

namespace {

ServerProber::Target mk_target(size_t index, const std::string &address, unsigned short port = 1194)
{
    return ServerProber::Target{index,
                                ServerProber::UDPEndpoint(openvpn_io::ip::make_address(address), port)};
}

// n remotes, each with addrs_each addresses, numbered so every address differs.
std::vector<std::vector<ServerProber::Target>> make_grid(size_t n, size_t addrs_each)
{
    std::vector<std::vector<ServerProber::Target>> per_remote;
    for (size_t i = 0; i < n; ++i)
    {
        std::vector<ServerProber::Target> addrs;
        for (size_t j = 0; j < addrs_each; ++j)
            addrs.push_back(mk_target(i, "10." + std::to_string(i / 250) + "." + std::to_string(i % 250) + "." + std::to_string(j + 1)));
        per_remote.push_back(std::move(addrs));
    }
    return per_remote;
}

size_t distinct_remotes(const std::vector<ServerProber::Target> &targets)
{
    std::set<size_t> seen;
    for (const auto &target : targets)
        seen.insert(target.index);
    return seen.size();
}

} // namespace

TEST(ProbeTargets, FewAddressesAreAllProbed)
{
    // 10 remotes x 3 = 30 addresses, under the ceiling: every one is probed.
    const auto sel = ServerProber::select_first_wave(make_grid(10, 3));
    EXPECT_EQ(sel.size(), 30u);
    EXPECT_EQ(distinct_remotes(sel), 10u);
}

TEST(ProbeTargets, ExactlyTheCeilingIsStillAllProbed)
{
    // The threshold is inclusive: 32 addresses are all probed, 33 are not.
    const auto exactly = ServerProber::select_first_wave(make_grid(16, 2));
    EXPECT_EQ(exactly.size(), ServerProber::max_probes_per_wave);
    EXPECT_EQ(distinct_remotes(exactly), 16u);

    auto over = make_grid(16, 2);
    over.push_back({mk_target(16, "10.9.9.9")});
    const auto past = ServerProber::select_first_wave(over);
    EXPECT_EQ(past.size(), 17u) << "one per remote once the ceiling is passed";
    EXPECT_EQ(distinct_remotes(past), 17u);
}

TEST(ProbeTargets, AboveTheCeilingOneProbePerRemote)
{
    // 20 remotes x 4 = 80 addresses: one probe each, so 20 probes.
    const auto sel = ServerProber::select_first_wave(make_grid(20, 4));
    EXPECT_EQ(sel.size(), 20u);
    EXPECT_EQ(distinct_remotes(sel), 20u) << "every remote gets exactly one";
}

TEST(ProbeTargets, NeverExceedsTheCeiling)
{
    // The pathological config: 600 remotes, 2 addresses each.
    const auto sel = ServerProber::select_first_wave(make_grid(600, 2));
    EXPECT_EQ(sel.size(), ServerProber::max_probes_per_wave);
    EXPECT_EQ(distinct_remotes(sel), ServerProber::max_probes_per_wave);
}

TEST(ProbeTargets, TakesRemotesInConfigurationOrder)
{
    // Which 32 is not arbitrary: configuration order is the user's preference.
    const auto sel = ServerProber::select_first_wave(make_grid(600, 2));
    for (size_t i = 0; i < sel.size(); ++i)
        EXPECT_EQ(sel[i].index, i) << "remote " << i << " out of order";
}

TEST(ProbeTargets, TakesTheResolversFirstAddress)
{
    // Not a family preference of ours: getaddrinfo already ordered these.
    auto per_remote = make_grid(40, 3);
    const auto sel = ServerProber::select_first_wave(per_remote);
    ASSERT_EQ(sel.size(), ServerProber::max_probes_per_wave);
    for (size_t i = 0; i < sel.size(); ++i)
        EXPECT_EQ(sel[i].ep, per_remote[i].front().ep) << "remote " << i;
}

TEST(ProbeTargets, EmptyInputSelectsNothing)
{
    EXPECT_TRUE(ServerProber::select_first_wave({}).empty());
    EXPECT_TRUE(ServerProber::select_first_wave({{}, {}}).empty());
}

// ---------------------------------------------------------------------------
// Paced sending.
//
// No assertions on wall-clock spacing: the interval only holds as finely as the
// system timer resolution allows, which is exactly what TimerResolution exists
// to manage, and asserting it would make these tests a measurement of the host.
// What is asserted is that pacing does not change the outcome.

namespace {

// Round-trip one probe at a given spacing; returns what the prober collected.
std::vector<ServerProber::Result> roundtrip_with_spacing(const Time::Duration &spacing)
{
    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x33));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    FakeProbeServer server(io_ctx, make_plain_config(frame, rng, time), stats);
    server.start();

    RemoteList::Ptr rl(new RemoteList("127.0.0.1", std::to_string(server.port()), Protocol(Protocol::UDPv4), "test"));
    rl->get_item(0)->set_ip_addr(IP::Addr::from_string("127.0.0.1"));

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr,
                                                       stats,
                                                       Time::Duration::milliseconds(300),
                                                       spacing);
    Collector cb;
    prober->start(&cb);
    io_ctx.run();
    server.stop();
    EXPECT_TRUE(cb.done);
    return cb.results;
}

} // namespace

TEST(ServerProber, ZeroSpacingSendsInline)
{
    // Spacing off is the pre-pacing behaviour, and the path the pure tests use.
    const auto results = roundtrip_with_spacing(Time::Duration());
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].remote_index, 0u);
}

TEST(ServerProber, SingleTargetWaveIsNotDelayedBySpacing)
{
    // A spacing long enough to force the timer path, short enough to finish
    // well inside the 300 ms window.
    const auto results = roundtrip_with_spacing(Time::Duration::milliseconds(20));
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].remote_index, 0u);
}

TEST(ServerProber, StopBeforeTheWindowFiresNoCallback)
{
    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x33));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    FakeProbeServer server(io_ctx, make_plain_config(frame, rng, time), stats);
    server.start();

    RemoteList::Ptr rl(new RemoteList("127.0.0.1", std::to_string(server.port()), Protocol(Protocol::UDPv4), "test"));
    rl->get_item(0)->set_ip_addr(IP::Addr::from_string("127.0.0.1"));

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr,
                                                       stats,
                                                       Time::Duration::milliseconds(300),
                                                       Time::Duration::milliseconds(50));
    Collector cb;
    prober->start(&cb);
    prober->stop(); // mid-wave: the pacing timer is armed, the window timer too
    io_ctx.run();   // must drain without running the callback or throwing

    EXPECT_FALSE(cb.done) << "stop() must not invoke the callback";
    server.stop();
}

// ---------------------------------------------------------------------------
// Several servers at once, each announcing something different.
//
// Every other test here runs one server with one fixed reply, so a bug that
// attached the right reply to the wrong remote would be invisible. These run
// several and check that each remote carries what its own server announced.
//
// Loopback RTTs are all ~0 and not controllable, so nothing here asserts on
// latency. Ranking itself is ProbeRank's own tests; this is the path into it.

namespace {

// One fake server per reply, each on its own loopback port, with a RemoteList
// pointing at them in the same order.
struct ProbeFixture
{
    openvpn_io::io_context io_ctx{1};
    Frame::Ptr frame{new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS))};
    StrongRandomAPI::Ptr rng{new FakeSecureRand(0x33)};
    Time time = Time::now();
    SessionStats::Ptr stats{new SessionStats()};
    std::vector<std::unique_ptr<FakeProbeServer>> servers;
    RemoteList::Ptr rl;

    Time::Duration spacing;

    explicit ProbeFixture(const std::vector<FakeProbeServer::Reply> &replies,
                          const std::set<size_t> &silent = {},
                          const Time::Duration &spacing_arg = Time::Duration())
        : spacing(spacing_arg)
    {
        std::string cfg_text;
        for (size_t i = 0; i < replies.size(); ++i)
        {
            auto srv = std::make_unique<FakeProbeServer>(io_ctx, make_plain_config(frame, rng, time), stats);
            srv->reply = replies[i];
            srv->silent = silent.count(i) != 0;
            srv->start();
            cfg_text += "remote 127.0.0.1 ";
            cfg_text += std::to_string(srv->port());
            cfg_text += " udp\n";
            servers.push_back(std::move(srv));
        }

        OptionList cfg;
        cfg.parse_from_config(cfg_text, nullptr);
        cfg.update_map();
        const RandomAPI::Ptr norng;
        rl.reset(new RemoteList(cfg, "", 0, nullptr, norng));
        const IP::Addr local = IP::Addr::from_string("127.0.0.1");
        for (size_t i = 0; i < replies.size(); ++i)
            rl->get_item(i)->set_ip_addr(local);
    }

    //! @param window how long replies have, measured from the last probe sent
    std::map<size_t, ServerProber::Result> run(const Time::Duration &window = Time::Duration::milliseconds(300))
    {
        const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                           rl,
                                                           make_plain_config(frame, rng, time),
                                                           nullptr,
                                                           stats,
                                                           window,
                                                           spacing);
        Collector cb;
        prober->start(&cb);

        // Bounded rather than run(): a server that never gets probed still
        // holds a receive, so a prober that finishes early would leave this
        // blocked forever. Returns as soon as the work runs out, so a passing
        // test does not wait; a broken one fails instead of hanging.
        io_ctx.run_for(std::chrono::seconds(3));
        for (auto &s : servers)
            s->stop();
        prober->stop();
        io_ctx.run();
        EXPECT_TRUE(cb.done);

        std::map<size_t, ServerProber::Result> by_remote;
        for (const auto &r : cb.results)
            by_remote.emplace(r.remote_index, r);
        EXPECT_EQ(by_remote.size(), cb.results.size()) << "two results for one remote";
        return by_remote;
    }
};


// ::1 is not universally present -- containers routinely disable IPv6 outright.
// What follows tests the prober's handling of the two families, not the host's
// network stack, so where the loopback does not exist the right answer is to
// skip rather than to fail.
bool ipv6_loopback_available()
{
    openvpn_io::io_context io(1);
    openvpn_io::ip::udp::socket s(io);
    openvpn_io::error_code ec;
    s.open(openvpn_io::ip::udp::v6(), ec);
    if (ec)
        return false;
    s.bind(openvpn_io::ip::udp::endpoint(openvpn_io::ip::make_address("::1"), 0), ec);
    return !ec;
}

} // namespace

TEST(ProbeExchange, EachRemoteCarriesItsOwnAnnouncement)
{
    ProbeFixture fx({{.priority = 7, .weight = 11, .max_latency_diff = 25},
                     {.priority = 0, .weight = 22, .max_latency_diff = 50},
                     {.priority = 3, .weight = 33, .max_latency_diff = 75}});
    const auto got = fx.run();
    ASSERT_EQ(got.size(), 3u);

    EXPECT_EQ(got.at(0).reply.priority, 7);
    EXPECT_EQ(got.at(0).reply.weight, 11);
    EXPECT_EQ(got.at(0).reply.max_latency_diff, 25);

    EXPECT_EQ(got.at(1).reply.priority, 0);
    EXPECT_EQ(got.at(1).reply.weight, 22);
    EXPECT_EQ(got.at(1).reply.max_latency_diff, 50);

    EXPECT_EQ(got.at(2).reply.priority, 3);
    EXPECT_EQ(got.at(2).reply.weight, 33);
    EXPECT_EQ(got.at(2).reply.max_latency_diff, 75);
}

TEST(ProbeExchange, SilentAddressIsProbedButNotRecorded)
{
    ProbeFixture fx({{.priority = 1}, {.priority = 2}, {.priority = 3}}, {1});
    const auto got = fx.run();

    ASSERT_EQ(got.size(), 2u) << "the silent server must not appear";
    EXPECT_EQ(got.count(1), 0u);
    EXPECT_EQ(got.at(0).reply.priority, 1);
    EXPECT_EQ(got.at(2).reply.priority, 3);

    EXPECT_EQ(fx.servers[1]->requests_received, 1u) << "it was probed, it just did not answer";
}

TEST(ProbeExchange, EveryRemoteIsProbedExactlyOnce)
{
    ProbeFixture fx({{}, {}, {}, {}});
    const auto got = fx.run();
    EXPECT_EQ(got.size(), 4u);
    for (size_t i = 0; i < fx.servers.size(); ++i)
        EXPECT_EQ(fx.servers[i]->requests_received, 1u) << "server " << i;
}

TEST(ProbeExchange, AnnouncedConnectLifetimeSurvivesTheWire)
{
    // Spelled out rather than braced: a one-element braced list here is
    // ambiguous with the deleted copy constructor on gcc 12 and older.
    const std::vector<FakeProbeServer::Reply> replies{{.connect_lifetime = 1234}};
    ProbeFixture fx(replies);
    const auto got = fx.run();
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got.at(0).reply.connect_lifetime, 1234);
    EXPECT_EQ(fx.servers[0]->last_request_flags, oob::request_flag_probe_only);
}

// ---------------------------------------------------------------------------
// IPv6.
//
// ServerProber opens one socket per family and picks between them per target
// (socket_for()). Until these existed the v6 branch had never been executed by
// any test, and the family question is central to what comes next: above the
// probe ceiling a remote is probed at one address, so which family the
// resolver put first decides what gets measured.

TEST(ProbeExchange, ProbesAnIPv6Server)
{
    if (!ipv6_loopback_available())
        GTEST_SKIP() << "no IPv6 loopback on this host";

    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x33));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    FakeProbeServer server(io_ctx, make_plain_config(frame, rng, time), stats, true, /*v6=*/true);
    server.reply.priority = 4;
    server.start();

    RemoteList::Ptr rl(new RemoteList("::1", std::to_string(server.port()), Protocol(Protocol::UDPv6), "test"));
    rl->get_item(0)->set_ip_addr(IP::Addr::from_string("::1"));

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr,
                                                       stats,
                                                       Time::Duration::milliseconds(300),
                                                       Time::Duration());
    Collector cb;
    prober->start(&cb);
    io_ctx.run();
    server.stop();

    ASSERT_TRUE(cb.done);
    ASSERT_EQ(cb.results.size(), 1u);
    EXPECT_EQ(cb.results[0].addr.to_string(), "::1");
    EXPECT_EQ(cb.results[0].reply.priority, 4);
}

TEST(ProbeExchange, ProbesBothFamiliesInOneRun)
{
    if (!ipv6_loopback_available())
        GTEST_SKIP() << "no IPv6 loopback on this host";

    // Both sockets open in the same run, each target routed to its own family.
    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x33));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    FakeProbeServer v4(io_ctx, make_plain_config(frame, rng, time), stats, true, false);
    FakeProbeServer v6(io_ctx, make_plain_config(frame, rng, time), stats, true, true);
    v4.reply.priority = 1;
    v6.reply.priority = 2;
    v4.start();
    v6.start();

    OptionList cfg;
    cfg.parse_from_config(std::string("remote 127.0.0.1 ") + std::to_string(v4.port()) + " udp\n"
                              + "remote ::1 " + std::to_string(v6.port()) + " udp\n",
                          nullptr);
    cfg.update_map();
    const RandomAPI::Ptr norng;
    RemoteList::Ptr rl(new RemoteList(cfg, "", 0, nullptr, norng));
    rl->get_item(0)->set_ip_addr(IP::Addr::from_string("127.0.0.1"));
    rl->get_item(1)->set_ip_addr(IP::Addr::from_string("::1"));

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr,
                                                       stats,
                                                       Time::Duration::milliseconds(300),
                                                       Time::Duration());
    Collector cb;
    prober->start(&cb);
    io_ctx.run();
    v4.stop();
    v6.stop();

    ASSERT_TRUE(cb.done);
    ASSERT_EQ(cb.results.size(), 2u) << "both families must answer";
    std::map<size_t, ServerProber::Result> got;
    for (const auto &r : cb.results)
        got.emplace(r.remote_index, r);
    EXPECT_EQ(got.at(0).addr.to_string(), "127.0.0.1");
    EXPECT_EQ(got.at(0).reply.priority, 1);
    EXPECT_EQ(got.at(1).addr.to_string(), "::1");
    EXPECT_EQ(got.at(1).reply.priority, 2);
}

// ---------------------------------------------------------------------------
// Paced waves, with enough targets to actually reach the pacing timer.
//
// A single-target run returns from send_next_paced() at "nothing left to wait
// for" without ever arming pace_timer, so the earlier pacing tests exercised
// everything around the mechanism and not the mechanism. These use three.

TEST(ProbeExchange, PacedWaveReachesEveryServer)
{
    ProbeFixture fx({{.priority = 1}, {.priority = 2}, {.priority = 3}},
                    {},
                    Time::Duration::milliseconds(20));
    const auto got = fx.run();

    ASSERT_EQ(got.size(), 3u) << "pacing must not lose a probe";
    EXPECT_EQ(got.at(0).reply.priority, 1);
    EXPECT_EQ(got.at(1).reply.priority, 2);
    EXPECT_EQ(got.at(2).reply.priority, 3);
    for (size_t i = 0; i < fx.servers.size(); ++i)
        EXPECT_EQ(fx.servers[i]->requests_received, 1u) << "server " << i;
}

TEST(ProbeExchange, WindowStartsAfterTheLastProbeNotTheFirst)
{
    // Three probes 100 ms apart put the last one on the wire at ~200 ms, well
    // past a 150 ms window. Were the window armed when the wave began it would
    // close first, cancel the pacing timer, and leave the tail unsent -- the
    // slowest remotes silently unprobed rather than merely unanswered.
    ProbeFixture fx({{.priority = 1}, {.priority = 2}, {.priority = 3}},
                    {},
                    Time::Duration::milliseconds(100));
    const auto got = fx.run(Time::Duration::milliseconds(150));

    EXPECT_EQ(got.size(), 3u) << "the wave outlived the window and was truncated";
    for (size_t i = 0; i < fx.servers.size(); ++i)
        EXPECT_EQ(fx.servers[i]->requests_received, 1u) << "server " << i << " never probed";
}

TEST(ProbeExchange, StoppingMidWaveLeavesTheTailUnsent)
{
    // stop() during a paced wave must cancel the pacing timer, not fire the
    // callback, and not send what had not gone out yet.
    openvpn_io::io_context io_ctx(1);
    Frame::Ptr frame(new Frame(Frame::Context(512, 2048, 512, 0, 16, BufAllocFlags::NO_FLAGS)));
    StrongRandomAPI::Ptr rng(new FakeSecureRand(0x33));
    Time time = Time::now();
    SessionStats::Ptr stats(new SessionStats());

    std::vector<std::unique_ptr<FakeProbeServer>> servers;
    std::string cfg_text;
    for (int i = 0; i < 3; ++i)
    {
        auto srv = std::make_unique<FakeProbeServer>(io_ctx, make_plain_config(frame, rng, time), stats);
        srv->start();
        cfg_text += "remote 127.0.0.1 ";
        cfg_text += std::to_string(srv->port());
        cfg_text += " udp\n";
        servers.push_back(std::move(srv));
    }
    OptionList cfg;
    cfg.parse_from_config(cfg_text, nullptr);
    cfg.update_map();
    const RandomAPI::Ptr norng;
    RemoteList::Ptr rl(new RemoteList(cfg, "", 0, nullptr, norng));
    const IP::Addr local = IP::Addr::from_string("127.0.0.1");
    for (int i = 0; i < 3; ++i)
        rl->get_item(i)->set_ip_addr(local);

    const auto prober = std::make_shared<ServerProber>(io_ctx,
                                                       rl,
                                                       make_plain_config(frame, rng, time),
                                                       nullptr,
                                                       stats,
                                                       Time::Duration::milliseconds(300),
                                                       Time::Duration::milliseconds(200));
    Collector cb;
    prober->start(&cb); // sends the first probe, arms the gap before the second

    // Let the first probe land, then stop well inside the 200 ms gap. The
    // servers are closed before draining because the two that were never
    // probed still hold a receive, which would keep run() from returning.
    io_ctx.run_for(std::chrono::milliseconds(50));
    prober->stop();
    for (auto &s : servers)
        s->stop();
    io_ctx.run();

    EXPECT_FALSE(cb.done) << "stop() must not invoke the callback";
    EXPECT_EQ(servers[0]->requests_received, 1u) << "the first probe had already gone";
    EXPECT_EQ(servers[1]->requests_received, 0u) << "the tail must not be sent after stop()";
    EXPECT_EQ(servers[2]->requests_received, 0u);
}
