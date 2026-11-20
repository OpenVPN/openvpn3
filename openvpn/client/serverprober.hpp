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
#include <memory>
#include <utility>
#include <vector>

#include <openvpn/io/io.hpp>

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
                 const Time::Duration &probe_window_arg)
        : io_context(io_context_arg),
          remote_list(std::move(remote_list_arg)),
          proto_config(std::move(proto_config_arg)),
          socket_protect(socket_protect_arg),
          stats(std::move(stats_arg)),
          probe_window(probe_window_arg),
          timer(io_context_arg),
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

        for (const auto &t : targets)
            send_probe(t);

        timer.expires_after(probe_window);
        timer.async_wait([self = shared_from_this()](const openvpn_io::error_code &error)
                         {
                             if (!error)
                                 self->finish(); });
    }

    //! Cancel probing without invoking the callback. Sockets stay open (transferable).
    void stop()
    {
        if (halt)
            return;
        halt = true;
        openvpn_io::error_code ec;
        timer.cancel();
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
     * Time elapsed since @p start, as the Time::Duration the ranking uses.
     * The monotonic clock rather than Time::now(), which reads GetTickCount64
     * on Windows and so steps in ~15.6 ms -- coarser than the ranking it feeds.
     */
    static Time::Duration elapsed_since(const std::chrono::steady_clock::time_point start)
    {
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - start)
                            .count();
        // Time::Duration counts 1/1024 s; round to nearest rather than truncate.
        const auto ticks = (us * 1024 + 500000) / 1000000;
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

    //! Collect every resolved UDP endpoint from the remote list.
    //! Each UDP remote's resolved endpoints, in resolver order; remotes that
    //! resolved to nothing are left out entirely.
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

    //! Wrap and send one probe request, recording the endpoint as pending.
    void send_probe(const Target &t)
    {
        UDPSocket *s = socket_for(t.ep);
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

        pending[t.ep] = Pending{.index = t.index, .sent = std::chrono::steady_clock::now(), .request_id = req.request_id};

        openvpn_io::error_code ec;
        s->send_to(buf.const_buffer(), t.ep, 0, ec);
        if (ec)
        {
            OPENVPN_LOG("ServerProber: send to " << t.ep << " failed: " << ec.message());
            pending.erase(t.ep);
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

    AsioTimer timer;
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
