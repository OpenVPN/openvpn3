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

/**
 * @file
 * Out-of-band server latency probing for best-server selection.
 *
 * Before the client connects, ServerProber sends a probe request (wrapped with the
 * configured control-channel protection) to every already-resolved remote
 * endpoint, waits a short asynchronous window for the replies, and reports
 * each responding server together with its measured round-trip time. A caller
 * (the connect loop) then reorders the remote list by latency/priority.
 *
 * Socket model: one native UDP socket *per address family*, each socket_protect'd,
 * with the source port bound implicitly by the first send. The sockets are held for
 * the prober's lifetime and can be released (release_socket) so the *winning*
 * remote's socket is adopted as the connection socket for the handshake shortcut,
 * with no rebind (that adoption is a later task).
 */

#ifndef OPENVPN_CLIENT_SERVERPROBER_H
#define OPENVPN_CLIENT_SERVERPROBER_H

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <memory>
#include <utility>
#include <vector>

#include <openvpn/io/io.hpp>

#include <openvpn/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_WIN
#include <windows.h>
#include <timeapi.h> // for timeBeginPeriod()
#endif
#include <openvpn/addr/ip.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/client/remotelist.hpp>
#include <openvpn/transport/socket_protect.hpp>
#include <openvpn/ssl/proto.hpp>
#include <openvpn/ssl/oob_probe.hpp>

namespace openvpn {

class ServerProber : public std::enable_shared_from_this<ServerProber>
{
  public:
    using UDPSocket = openvpn_io::ip::udp::socket;
    using UDPEndpoint = openvpn_io::ip::udp::endpoint;

    //! One responding server, with its measured latency and advertised parameters.
    struct Result
    {
        size_t remote_index = 0; //!< index of the remote in the RemoteList
        IP::Addr addr;           //!< the address that answered
        unsigned short port = 0; //!< the port that answered
        Time::Duration rtt;      //!< measured probe round-trip time
        oob::ProbeReply reply;   //!< priority / weight / connect_lifetime / flags
    };

    struct NotifyCallback
    {
        virtual ~NotifyCallback() = default;
        //! called once when the probe window closes, with every reply collected
        virtual void server_probe_done(std::vector<Result> results) = 0;
    };

    //! Construct a prober for the already-resolved remotes in @p remote_list_arg,
    //! wrapping probes with the control-channel protection from @p proto_config_arg.
    //! Opens no socket and sends nothing; call start() to probe.
    ServerProber(openvpn_io::io_context &io_context_arg,
                 RemoteList::Ptr remote_list_arg,
                 ProtoContext::ProtoConfig::Ptr proto_config_arg,
                 SocketProtect *socket_protect_arg,
                 SessionStats::Ptr stats_arg,
                 const Time::Duration &probe_window_arg,
                 const Time::Duration &probe_spacing_arg = Time::Duration::milliseconds(default_probe_spacing_ms))
        : io_context(io_context_arg),
          remote_list(std::move(remote_list_arg)),
          proto_config(std::move(proto_config_arg)),
          socket_protect(socket_protect_arg),
          stats(std::move(stats_arg)),
          probe_window(probe_window_arg),
          probe_spacing(probe_spacing_arg),
          timer(io_context_arg),
          pace_timer(io_context_arg),
          probe_wrap(proto_config, stats)
    {
    }

    //! Cancels any in-flight probe; see stop().
    ~ServerProber()
    {
        stop();
    }

    /**
     * @brief Begin probing. @p cb->server_probe_done() fires exactly once, when the
     * probe window elapses (or immediately if there is nothing to probe).
     */
    void start(NotifyCallback *cb)
    {
        notify_callback = cb;

        const std::vector<Target> targets = select_first_wave(gather_per_remote());
        if (targets.empty())
        {
            finish();
            return;
        }

        send_wave(targets); // arms the reply window once the last probe is away
    }

    //! Cancel probing without invoking the callback. Sockets stay open (transferable).
    void stop()
    {
        if (halt)
            return;
        halt = true;
        openvpn_io::error_code ec;
        timer.cancel();
        pace_timer.cancel();
        resolution.reset();
        if (sock_v4)
            sock_v4->cancel(ec);
        if (sock_v6)
            sock_v6->cancel(ec);
    }

    /**
     * @brief Hand off the probe socket for an address family so it can be adopted
     * as the connection socket (source port preserved, no rebind).
     *
     * The adopting transport must be its only reader, so anything we still have
     * armed on it is cancelled. Nothing of ours re-arms behind that: queue_recv()
     * looks the socket up by family, and it is gone once moved out.
     *
     * @return the socket, or nullptr if none was opened for that family
     */
    std::unique_ptr<UDPSocket> release_socket(const IP::Addr::Version v)
    {
        if (v == IP::Addr::Version::UNSPEC)
            return nullptr;

        std::unique_ptr<UDPSocket> &slot = (v == IP::Addr::Version::V4) ? sock_v4 : sock_v6;
        if (slot)
        {
            openvpn_io::error_code ec;
            slot->cancel(ec);
        }
        return std::move(slot);
    }

    /**
     * @brief Time elapsed since @p start, as the Time::Duration the ranking uses.
     *
     * The monotonic clock rather than Time::now(), which reads GetTickCount64
     * on Windows and so steps in ~15.6 ms -- coarser than the ranking it feeds.
     *
     * @param start when the probe was sent
     * @return the interval since then, to the nearest 1/1024 s
     */
    static Time::Duration elapsed_since(const std::chrono::steady_clock::time_point start)
    {
        const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                    std::chrono::steady_clock::now() - start)
                                    .count();
        // Time::Duration counts 1/1024 s; round to nearest rather than truncate.
        const auto ticks = (elapsed_us * 1024 + 500000) / 1000000;
        return Time::Duration::binary_ms(static_cast<Time::type>(ticks < 0 ? 0 : ticks));
    }

    struct Target
    {
        size_t index;
        UDPEndpoint ep;
    };

    /**
     * Probe ceiling for a single wave. The specification suggests probing every
     * resolved address only while there are few of them ("a small number like
     * 32") and one probe per remote above that; it does not fix the number.
     * The same ceiling bounds each later wave, so no configuration turns
     * probing into an unbounded burst.
     */
    static constexpr size_t max_probes_per_wave = 32;

    /**
     * Default gap between two probe sends, in ms.
     *
     * Not a specification requirement; it exists so a wave does not arrive as
     * one burst. What drops bursts is not scan detection, which works over
     * seconds and is indifferent to this, but the new-flow rate limiting in
     * CGNAT, conntrack tables and cloud egress, which is a token bucket and
     * very much is not -- and a dropped probe is indistinguishable from a
     * server that never answered, so a rate-limited client would quietly rank
     * healthy remotes as dead. At this gap a full wave takes about 160 ms.
     */
    static constexpr unsigned int default_probe_spacing_ms = 5;

    /**
     * Pick the first wave of probe targets from each remote's addresses.
     *
     * While there are few addresses in total, probe every one of them. Above
     * that, fall back to one probe per remote: the address the resolver put
     * first, because getaddrinfo has already applied RFC 6724 and the local
     * policy table and so knows more than we do about which family to prefer,
     * and the remotes in configuration order, that order being the user's own
     * statement of preference. Either way the wave is capped at
     * max_probes_per_wave.
     *
     * Addresses left unprobed here are not discarded; they are what a later
     * wave draws on once the replies say which are worth a packet.
     *
     * @param per_remote each remote's resolved endpoints, in resolver order
     * @return the targets to probe, never more than max_probes_per_wave
     */
    static std::vector<Target> select_first_wave(const std::vector<std::vector<Target>> &per_remote)
    {
        size_t total = 0;
        for (const auto &addrs : per_remote)
            total += addrs.size();

        std::vector<Target> out;
        if (total <= max_probes_per_wave)
        {
            out.reserve(total);
            for (const auto &addrs : per_remote)
                out.insert(out.end(), addrs.begin(), addrs.end());
            return out;
        }

        out.reserve(std::min(per_remote.size(), max_probes_per_wave));
        for (const auto &addrs : per_remote)
        {
            if (out.size() >= max_probes_per_wave)
                break;
            if (!addrs.empty())
                out.push_back(addrs.front());
        }
        return out;
    }

  private:
    /**
     * @brief Holds the system timer resolution fine enough that short waits
     *        mean what they say, for as long as the guard exists.
     *
     * Windows runs a ~15.6 ms system tick by default, and an asio timer waits on
     * it, so asking for 1 ms and asking for 5 ms both come back at about 15.6 ms --
     * the pacing interval would be whatever the machine happened to be set to
     * rather than what we chose. Raising the resolution costs power, so the guard
     * is held only while a probe run is in flight, a few hundred milliseconds, and
     * dropped immediately after. Everywhere else a short wait is already honoured
     * and this does nothing.
     */
    class TimerResolution
    {
      public:
        TimerResolution()
        {
#ifdef OPENVPN_PLATFORM_WIN
            raised_ = (::timeBeginPeriod(period_ms) == TIMERR_NOERROR);
#endif
        }

        ~TimerResolution()
        {
#ifdef OPENVPN_PLATFORM_WIN
            if (raised_)
                ::timeEndPeriod(period_ms);
#endif
        }

        TimerResolution(const TimerResolution &) = delete;
        TimerResolution &operator=(const TimerResolution &) = delete;
        TimerResolution(TimerResolution &&) = delete;
        TimerResolution &operator=(TimerResolution &&) = delete;

      private:
#ifdef OPENVPN_PLATFORM_WIN
        static constexpr UINT period_ms = 1;
        bool raised_ = false;
#endif
    };

    struct Pending
    {
        size_t index = 0;
        std::chrono::steady_clock::time_point sent;
        std::uint64_t request_id = 0;
    };

    struct RecvCtx
    {
        BufferAllocated buf;
        UDPEndpoint sender;
    };

    /**
     * Each UDP remote's resolved endpoints, in resolver order.
     * @return one entry per remote that resolved to something; a remote with
     *         no usable endpoint is left out entirely
     */
    std::vector<std::vector<Target>> gather_per_remote() const
    {
        std::vector<std::vector<Target>> per_remote;
        if (!remote_list)
            return per_remote;
        for (size_t i = 0; i < remote_list->size(); ++i)
        {
            const RemoteList::Item::Ptr item = remote_list->get_item(i);
            if (!item || !item->transport_protocol.is_udp())
                continue;
            std::vector<Target> addrs;
            try
            {
                UDPEndpoint ep;
                for (size_t j = 0; item->get_endpoint(ep, j); ++j)
                    addrs.push_back({i, ep});
            }
            catch (const std::exception &)
            {
                continue; // unparsable port: skip the whole remote
            }
            if (!addrs.empty())
                per_remote.push_back(std::move(addrs));
        }
        return per_remote;
    }

    //! Lazily open (and socket_protect) the per-family socket, arming its receive.
    UDPSocket *socket_for(const UDPEndpoint &target)
    {
        const bool v4 = target.address().is_v4();
        std::unique_ptr<UDPSocket> &slot = v4 ? sock_v4 : sock_v6;
        const openvpn_io::ip::udp proto = v4 ? openvpn_io::ip::udp::v4() : openvpn_io::ip::udp::v6();

        if (!slot)
        {
            auto s = std::make_unique<UDPSocket>(io_context);
            openvpn_io::error_code ec;
            s->open(proto, ec);
            if (ec)
            {
                OPENVPN_LOG("ServerProber: socket open failed: " << ec.message());
                return nullptr;
            }
            if (socket_protect
                && !socket_protect->socket_protect(s->native_handle(),
                                                   IP::Addr::from_asio(target.address())))
                OPENVPN_LOG("ServerProber: socket_protect failed (continuing)");
            slot = std::move(s);
            queue_recv(v4);
        }
        return slot.get();
    }

    /**
     * @brief Send @p wave one probe at a time, probe_spacing apart.
     *
     * The first goes out immediately, so a single-target run is not delayed at
     * all, and no wait follows the last one. A zero spacing sends the whole
     * wave inline, which is what the tests use to take the clock out of play.
     *
     * @param wave the targets to probe, in the order to send them
     */
    void send_wave(const std::vector<Target> &wave)
    {
        if (probe_spacing <= Time::Duration())
        {
            for (const auto &target : wave)
                send_probe(target);
            arm_window();
            return;
        }

        // Short waits are only honoured at a fine system timer resolution; held
        // until the run ends, see TimerResolution.
        resolution.emplace();
        pacing = wave;
        pace_pos = 0;
        send_next_paced();
    }

    /**
     * @brief Send the next queued probe and arm the gap before the one after it.
     *
     * Arms the reply window instead once the wave is exhausted.
     */
    void send_next_paced()
    {
        if (halt || pace_pos >= pacing.size())
            return;
        send_probe(pacing[pace_pos++]);
        if (pace_pos >= pacing.size())
        {
            arm_window();
            return;
        }

        pace_timer.expires_after(probe_spacing);
        pace_timer.async_wait([self = shared_from_this()](const openvpn_io::error_code &error)
                              {
                                  if (!error && !self->halt)
                                      self->send_next_paced(); });
    }

    /**
     * @brief Start the window the replies have to arrive in.
     *
     * It runs from the moment the last probe is away, not the first. Pacing a
     * full wave takes a sixth of a second, so a window started at the first
     * probe would give the last remote that much less time to answer than the
     * first -- and a window shorter than the wave would close before the tail
     * had even been sent, cancelling the pacing timer and leaving those
     * remotes unprobed and indistinguishable from silent ones.
     */
    void arm_window()
    {
        timer.expires_after(probe_window);
        timer.async_wait([self = shared_from_this()](const openvpn_io::error_code &error)
                         {
                             if (!error)
                                 self->finish(); });
    }

    //! Wrap and send one probe request, recording the endpoint as pending.
    void send_probe(const Target &target)
    {
        UDPSocket *s = socket_for(target.ep);
        if (!s)
            return;

        // encode the probe request payload, then wrap it with the control-channel
        // protection so a standard server accepts it
        BufferAllocated buf;
        buf.reset(512, 2048, BufAllocFlags::NO_FLAGS);
        // from the RNG, not a counter: the id binds a reply to this request, so
        // it has to be unpredictable
        // probe only: we measure the round trip and connect separately, so the
        // server may forget the exchange at once. Without it a connect_lifetime
        // of 0 would mean the server had rejected the connection attempt.
        const oob::ProbeRequest req{
            .request_id = proto_config->rng->rand_get<std::uint64_t>(),
            .timestamp = static_cast<std::uint64_t>(Time::now().seconds_since_epoch()),
            .flags = oob::request_flag_probe_only,
        };
        if (!req.write(buf))
        {
            return;
        }
        BufferAllocated work;
        probe_wrap.wrap(buf, work);

        pending[target.ep] = Pending{.index = target.index, .sent = std::chrono::steady_clock::now(), .request_id = req.request_id};

        openvpn_io::error_code ec;
        s->send_to(buf.const_buffer(), target.ep, 0, ec);
        if (ec)
        {
            OPENVPN_LOG("ServerProber: send to " << target.ep << " failed: " << ec.message());
            pending.erase(target.ep);
        }
    }

    //! Arm the next receive on the v4 or v6 socket; re-armed after every datagram
    //! until halt, or until that socket is released (it is then gone).
    void queue_recv(const bool v4)
    {
        std::unique_ptr<UDPSocket> &slot = v4 ? sock_v4 : sock_v6;
        if (halt || !slot || !slot->is_open())
            return;
        auto rc = std::make_shared<RecvCtx>();
        rc->buf.reset(0, 1600, BufAllocFlags::NO_FLAGS);
        slot->async_receive_from(rc->buf.mutable_buffer(), rc->sender, [self = shared_from_this(), v4, rc](const openvpn_io::error_code &error, const size_t bytes_recvd) mutable
                                 {
                                  if (self->halt)
                                      return;
                                  if (!error && bytes_recvd)
                                  {
                                      rc->buf.set_size(bytes_recvd);
                                      // Boundary guard: nothing may escape an asio handler -- it
                                      // would unwind out of io_context::run() and kill the connect.
                                      // Broad by intent: untrusted input parsed by buffer/crypto
                                      // code whose exception types vary by SSL backend.
                                      try
                                      {
                                          self->handle_reply(rc->sender, rc->buf);
                                      }
                                      catch (const std::exception &e)
                                      {
                                          self->stats->error(Error::CC_ERROR);
                                          OPENVPN_LOG("ServerProber: exception processing reply from "
                                                      << rc->sender << ": " << e.what());
                                      }
                                  }
                                  // re-arm unless the error is a cancel/close
                                  if (!self->halt && error != openvpn_io::error::operation_aborted)
                                      self->queue_recv(v4); });
    }

    //! Unwrap a probe reply and record a Result, ignoring anything unsolicited.
    void handle_reply(const UDPEndpoint &sender, BufferAllocated &buf)
    {
        auto it = pending.find(sender);
        if (it == pending.end())
            return; // unsolicited or already recorded
        const Time::Duration rtt = elapsed_since(it->second.sent);

        BufferAllocated work;
        ProtoSessionID src;
        PacketIDControl pid;
        if (probe_wrap.unwrap(buf, work, src, pid) != ProtoContext::UnwrapStatus::OK)
            return;

        const auto reply = oob::probe_reply_find(buf);
        if (!reply)
            return;
        // the endpoint above can be forged off-path; the echoed request_id is
        // what an attacker cannot guess
        if (reply->request_id != it->second.request_id)
        {
            return;
        }

        results.push_back(Result{.remote_index = it->second.index,
                                 .addr = IP::Addr::from_asio(it->first.address()),
                                 .port = it->first.port(),
                                 .rtt = rtt,
                                 .reply = *reply});

        pending.erase(it); // one result per endpoint
    }

    //! Close the probe window and hand the replies to the callback, once. No-op if
    //! stopped -- an already-expired timer's handler can still reach us.
    void finish()
    {
        if (finished || halt)
            return;
        finished = true;
        stop(); // cancels timer + outstanding receives, leaves sockets open

        NotifyCallback *cb = notify_callback;
        notify_callback = nullptr;
        if (cb)
            cb->server_probe_done(std::move(results));
    }

    openvpn_io::io_context &io_context;
    RemoteList::Ptr remote_list;
    ProtoContext::ProtoConfig::Ptr proto_config;
    SocketProtect *socket_protect;
    SessionStats::Ptr stats;
    Time::Duration probe_window;
    Time::Duration probe_spacing;

    AsioTimer timer;
    AsioTimer pace_timer;
    std::vector<Target> pacing;
    size_t pace_pos = 0;
    std::optional<TimerResolution> resolution;
    ProtoContext::ProbeWrap probe_wrap;

    std::unique_ptr<UDPSocket> sock_v4;
    std::unique_ptr<UDPSocket> sock_v6;

    std::map<UDPEndpoint, Pending> pending;
    std::vector<Result> results;

    NotifyCallback *notify_callback = nullptr;
    bool halt = false;
    bool finished = false;
};

} // namespace openvpn

#endif
