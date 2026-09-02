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
 * @brief A userspace UDP transport server: listener, peer demux, and flood gate.
 *
 * @details
 * Implements the @c TransportServer and @c TransportClientInstance::Send seams
 * (`openvpn/transport/server/transbase.hpp`) over a single bound UDP socket,
 * using the existing @c UDPTransport::UDPLink for the read loop and framing.
 *
 * The server owns one socket for every client. Inbound datagrams are demuxed by
 * source endpoint to a @c ServerProto::Session, and each session is handed a
 * per-peer sender that writes back to that endpoint.
 *
 * A datagram from an unknown endpoint must pass a stateless gate before any
 * per-client state exists. @c PsidCookie::intercept() runs the HMAC session-ID
 * cookie exchange: the server's reply to the client's HARD_RESET is computed,
 * not stored, so it allocates nothing and offers no retransmit amplification,
 * and a session is created only once the cookie comes back verified.
 *
 * @c intercept() is called before @c validate_initial_packet(), which matters:
 * both packets of the cookie exchange arrive with no session, but only the
 * first is a HARD_RESET, and prevalidation accepts nothing else. Prevalidating
 * first would therefore reject every cookie ACK and no client could connect.
 * The cookie HMAC-checks both packets itself, so nothing is lost.
 *
 * The cookie gate covers tls-auth and tls-crypt-v2. With plain tls-crypt (v1),
 * or with neither configured, @c intercept() returns @c DECLINE_HANDLING; there
 * the packet is the client's first, @c validate_initial_packet() is the only
 * pre-TLS filter, and no proof of address ownership is obtained. That is an
 * inherited property of the cookie design, not a choice made here, and it is
 * why a server configuration should prefer tls-crypt-v2 or tls-auth.
 */

#ifndef OPENVPN_SERVER_UDPTRANSSERV_H
#define OPENVPN_SERVER_UDPTRANSSERV_H

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <sstream>
#include <string>
#include <utility>

#include <openvpn/io/io.hpp>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/bigmutex.hpp> // OPENVPN_ASYNC_HANDLER, expanded by UDPLink
#include <openvpn/addr/ip.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/logger.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/server/manage.hpp>
#include <openvpn/server/peeraddr.hpp>
#include <openvpn/server/peerid.hpp>
#include <openvpn/server/peerstats.hpp>
#include <openvpn/server/servhalt.hpp>
#include <openvpn/server/servproto.hpp>
#include <openvpn/ssl/psid.hpp>
#include <openvpn/ssl/psid_cookie.hpp>
#include <openvpn/ssl/psid_cookie_impl.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/transport/server/transbase.hpp>
#include <openvpn/transport/sockbuf.hpp>
#include <openvpn/transport/udplink.hpp>

namespace openvpn::UDPTransportServer {

using AsioEndpoint = openvpn_io::ip::udp::endpoint;

/**
 * @brief Listener and tuning parameters for the UDP transport server.
 */
struct Config : public RC<thread_unsafe_refcount>
{
    using Ptr = RCPtr<Config>;

    /** Local address to bind. Use @c "0.0.0.0" or @c "::" to accept on any. */
    std::string bind_addr = "0.0.0.0";

    /** Local UDP port to bind. */
    unsigned short port = 1194;

    /** Frame geometry, supplying buffer headroom and capacity. Required. */
    Frame::Ptr frame;

    /** Server-wide statistics sink. Required. */
    SessionStats::Ptr stats;

    /** Upper bound on concurrent sessions; further clients are dropped. */
    size_t max_clients = 1024;

    /**
     * Socket receive buffer in bytes, or 0 to leave the kernel default.
     * @note Applied via @c SockBuf::set_rcvbuf, which prefers the privileged
     *  @c SO_RCVBUFFORCE so a request larger than @c net.core.rmem_max is
     *  honoured without host tuning. Without @c CAP_NET_ADMIN it falls back to
     *  plain @c SO_RCVBUF and is silently clamped to that ceiling; the size
     *  actually granted is logged at startup either way.
     */
    int rcvbuf = 0;

    /** Socket send buffer in bytes, or 0 to leave the kernel default.
     *  Same forcing and fallback behaviour as @c rcvbuf. */
    int sndbuf = 0;

    /** Concurrent outstanding reads posted on the socket. */
    int n_parallel = 4;

    /** Seconds between sweeps that reap sessions which ended without a packet. */
    unsigned int reap_interval = 5;
};

/**
 * @brief Hashable representation of a client's transport address for the cookie HMAC.
 *
 * @details
 * The psid cookie is an HMAC over a byte slab identifying the client, so the
 * slab must be reproducible across the two packets of the handshake and must
 * not collide between distinct clients. IPv4 addresses are encoded in their
 * IPv4-mapped IPv6 form so that v4 and v6 clients share one fixed-width layout
 * and a v4 address cannot alias a v6 one. Bytes are written explicitly rather
 * than by copying a struct, so no padding enters the hash.
 */
class ClientAddrInfo : public PsidCookieAddrInfoBase
{
  public:
    /**
     * @brief Build the address slab for one client endpoint.
     * @param endpoint The client's source address and port. Copied, so this
     *  object is safe to construct from a temporary -- @c get_impl_info()
     *  hands out a pointer to the copy, which several tests were previously
     *  taking against a dangling reference.
     */
    explicit ClientAddrInfo(const AsioEndpoint &endpoint)
        : endpoint_(endpoint)
    {
        const openvpn_io::ip::address addr = endpoint.address();
        if (addr.is_v4())
        {
            // IPv4-mapped IPv6: 80 zero bits, 16 one bits, then the v4 address.
            slab_[10] = 0xff;
            slab_[11] = 0xff;
            const auto b = addr.to_v4().to_bytes();
            std::memcpy(slab_.data() + 12, b.data(), 4);
        }
        else
        {
            const auto b = addr.to_v6().to_bytes();
            std::memcpy(slab_.data(), b.data(), 16);
        }
        const std::uint16_t port = endpoint.port();
        slab_[16] = static_cast<unsigned char>((port >> 8) & 0xff);
        slab_[17] = static_cast<unsigned char>(port & 0xff);
    }

    /**
     * @brief Provide the reproducible byte slab identifying this client.
     * @param[out] slab_size Set to the slab length in bytes.
     * @return Pointer to the slab, valid for this object's lifetime.
     */
    const unsigned char *get_abstract_cli_addrport(size_t &slab_size) const override
    {
        slab_size = slab_.size();
        return slab_.data();
    }

    /**
     * @brief Provide the transport-specific endpoint for the cookie reply.
     * @return Pointer to the @c AsioEndpoint this object was built from, which
     *  the cookie transport uses as the reply destination.
     */
    const void *get_impl_info() const override
    {
        return &endpoint_;
    }

  private:
    static constexpr size_t SLAB_SIZE = 16 + sizeof(std::uint16_t);

    AsioEndpoint endpoint_;
    std::array<unsigned char, SLAB_SIZE> slab_{};
};

/**
 * @brief Read the DATA_V2 peer-id out of a raw (still-encrypted) packet, if present.
 *
 * @details
 * Mirrors the peer-id parsing `ProtoContext::PacketType` does internally for
 * DATA_V2 packets (`ssl/proto.hpp`): opcode 9 in the top 5 bits of the first
 * byte, a 24-bit peer id in the low bits of the 4-byte big-endian header.
 * Duplicated here, rather than reused from `ProtoContext`, because that
 * parsing is a private nested type requiring a live session's `ProtoContext&`
 * to construct, and this call site has no session yet -- finding one is the
 * point.
 *
 * This is a **routing hint only, not an authentication step**: it exists so
 * an unrecognized source endpoint can be tried against a specific *candidate*
 * session (peer float) instead of falling straight through to the
 * new-connection path. The candidate is only ever accepted if that session's
 * own `transport_recv()` successfully decrypts and authenticates the packet
 * against its real negotiated key; an attacker guessing or replaying someone
 * else's peer id gets nothing beyond a failed decrypt on that session; no
 * different from a failed decrypt on any other invalid packet.
 *
 * @param buf The raw packet as received from the socket. Not modified.
 * @return The peer id, or @c std::nullopt if @p buf is too short, is not a
 *  DATA_V2 packet, or its peer id is the wire "undefined" sentinel.
 */
inline std::optional<int> extract_peer_id_hint(const Buffer &buf)
{
    constexpr unsigned int OPCODE_SHIFT = 3;
    constexpr unsigned int DATA_V2 = 9;
    constexpr std::uint32_t OP_PEER_ID_UNDEF = 0x00FFFFFF;

    if (buf.size() < 4)
        return std::nullopt;

    if ((static_cast<unsigned int>(buf[0]) >> OPCODE_SHIFT) != DATA_V2)
        return std::nullopt;

    std::uint32_t op32;
    std::memcpy(&op32, buf.c_data(), sizeof(op32));
    const std::uint32_t peer_id = ntohl(op32) & OP_PEER_ID_UNDEF;
    if (peer_id == OP_PEER_ID_UNDEF)
        return std::nullopt;

    return static_cast<int>(peer_id);
}

/**
 * @brief Report whether a datagram is shaped like a client's opening packet.
 *
 * @details
 * A stateless shape check, not authentication: the only opcodes that may
 * legitimately create a session are the client hard resets. Used on the path
 * where no psid cookie is configured and @c validate_initial_packet() has no
 * prevalidator to consult, so it accepts everything.
 *
 * Defers to @c ProtoContext::PsidCookieHelper, which the cookie gate already
 * uses for the same question, rather than re-deriving the opcode here.
 *
 * @param buf The raw packet as received. Not modified.
 * @return True if @p buf is non-empty and carries a client hard-reset opcode.
 */
inline bool looks_like_client_reset(const Buffer &buf)
{
    if (buf.empty())
        return false;
    return ProtoContext::PsidCookieHelper(buf[0]).is_clients_initial_reset();
}

class Server;

/**
 * @brief Per-client sender: writes datagrams back to one client's endpoint.
 *
 * @details
 * Handed to @c ServerProto::Session as its @c TransportLink::send. Holds a
 * non-owning pointer to the server, which owns the socket; the server outlives
 * every session, and @c stop() clears the pointer during teardown so a late
 * send cannot reach a destroyed server.
 */
class PeerSend : public TransportClientInstance::Send
{
  public:
    using Ptr = RCPtr<PeerSend>;

    /**
     * @brief Construct the per-client sender.
     * @param server The owning server, which holds the socket. Borrowed.
     * @param endpoint The client's address, used as the send destination.
     */
    PeerSend(Server *server, const AsioEndpoint &endpoint);

    /**
     * @brief Report whether this sender can still transmit.
     * @return True until @c stop() is called.
     */
    bool defined() const override
    {
        return !halt_;
    }

    /**
     * @brief Halt this sender and drop its reference to the server.
     * @details Idempotent.
     */
    void stop() override
    {
        halt_ = true;
        server_ = nullptr;
    }

    /**
     * @brief Send a const datagram to this client.
     * @param buf The encapsulated packet to transmit.
     * @return True if the datagram was written in full.
     */
    bool transport_send_const(const Buffer &buf) override;

    /**
     * @brief Send a mutable datagram to this client.
     * @param buf The encapsulated packet to transmit. Not modified.
     * @return True if the datagram was written in full.
     */
    bool transport_send(BufferAllocated &buf) override
    {
        return transport_send_const(buf);
    }

    /**
     * @brief Human-readable description of this client's transport, for logging.
     * @return A string of the form @c "UDP <addr>:<port>".
     */
    const std::string &transport_info() const override
    {
        return info_;
    }

    /**
     * @brief Report whether new byte counters are available since the last poll.
     * @return True if any traffic has been counted since @c stats_poll().
     */
    bool stats_pending() const override
    {
        return stats_.rx_bytes != polled_.rx_bytes || stats_.tx_bytes != polled_.tx_bytes;
    }

    /**
     * @brief Retrieve this client's cumulative byte and packet counters.
     * @return The current counters. Also marks them as polled.
     */
    PeerStats stats_poll() override
    {
        polled_ = stats_;
        return stats_;
    }

    /**
     * @brief Account for a received datagram.
     * @param bytes Size of the datagram in bytes.
     */
    void count_in(const size_t bytes)
    {
        stats_.rx_bytes += bytes;
    }

    /**
     * @brief The client endpoint this sender targets.
     * @return The destination address and port.
     */
    const AsioEndpoint &endpoint() const
    {
        return endpoint_;
    }

    /**
     * @brief Redirect this sender to a new endpoint after a verified peer float.
     * @param endpoint The client's new source address and port.
     */
    void set_endpoint(const AsioEndpoint &endpoint)
    {
        endpoint_ = endpoint;
        std::ostringstream os;
        os << "UDP " << endpoint_.address().to_string() << ':' << endpoint_.port();
        info_ = os.str();
    }

  private:
    Server *server_;
    AsioEndpoint endpoint_;
    std::string info_;
    PeerStats stats_;
    PeerStats polled_;
    bool halt_ = false;
};

/**
 * @brief UDP listener owning the socket, the session table, and the flood gate.
 *
 * @details
 * Single-threaded: every method must run on the owning @c io_context's thread.
 * The session table maps client endpoint to protocol session; a session holds a
 * reference to its @c PeerSend, and @c PeerSend holds only a raw pointer back,
 * so no ownership cycle exists.
 */
class Server : public TransportServer
{
    friend class UDPTransport::UDPLink<Server *>;

  public:
    using Ptr = RCPtr<Server>;

    /**
     * @brief Construct the server.
     * @param io_context Event loop the socket and timers attach to.
     * @param config Listener configuration. Must carry a frame and a stats sink.
     * @param proto_factory Protocol factory producing per-client sessions; also
     *  supplies the prevalidation gate and the cookie's protocol configuration.
     * @throws openvpn::Exception if the configuration is incomplete.
     */
    Server(openvpn_io::io_context &io_context,
           Config::Ptr config,
           ServerProto::Factory::Ptr proto_factory)
        : io_context_(io_context),
          config_(std::move(config)),
          proto_factory_(std::move(proto_factory)),
          socket_(io_context),
          reap_timer_(io_context)
    {
        if (!config_ || !config_->frame || !config_->stats)
            throw Exception("UDPTransportServer: config requires frame and stats");
        if (!proto_factory_)
            throw Exception("UDPTransportServer: proto factory required");

        peer_ids_ = PeerId::Table<AsioEndpoint>(config_->max_clients);
    }

    /**
     * @brief Open the socket, begin accepting datagrams, and arm the reaper.
     * @details Binds the configured address and port, applies socket buffer
     *  sizes if requested, initializes the cookie machinery, and posts the
     *  first reads. Idempotent.
     * @throws openvpn_io::system_error if the socket cannot be opened or bound.
     */
    void start() override
    {
        if (started_)
            return;
        started_ = true;

        const IP::Addr bind_ip = IP::Addr::from_string(config_->bind_addr, "bind_addr");
        const AsioEndpoint local(bind_ip.to_asio(), config_->port);

        socket_.open(local.protocol());
        socket_.set_option(openvpn_io::ip::udp::socket::reuse_address(true));
        // Named for the log statement to consume; the calls carry the side
        // effect, so they must not fold into OPENVPN_LOG, which some embedders
        // define away.
        [[maybe_unused]] const SockBuf::Result rcv = SockBuf::set_rcvbuf(socket_, config_->rcvbuf);
        [[maybe_unused]] const SockBuf::Result snd = SockBuf::set_sndbuf(socket_, config_->sndbuf);
        socket_.bind(local);
        local_ = socket_.local_endpoint();

        // Must precede any intercept() call so every thread shares one cookie key.
        PsidCookieImpl::pre_threading_setup();
        psid_cookie_.reset(new PsidCookieImpl(proto_factory_.get()));
        psid_cookie_->provide_psid_cookie_transport(
            PsidCookieTransportBase::Ptr(new CookieTransport(this)));

        link_.reset(new LinkImpl(this,
                                 socket_,
                                 (*config_->frame)[Frame::READ_LINK_UDP],
                                 config_->stats));
        link_->start(config_->n_parallel);

        OPENVPN_LOG("UDP server listening on " << local_endpoint_info());
        OPENVPN_LOG("UDP socket buffers: rcv " << rcv.to_string()
                                               << ", snd " << snd.to_string());
        schedule_reap();
    }

    /**
     * @brief Stop the listener and tear down every session.
     * @details Cancels the reaper, notifies every connected client with a
     *  RESTART message (matching OpenVPN 2's server-side @c
     *  explicit-exit-notify: a graceful shutdown should read as a clean,
     *  expected disconnect on the client, not a network failure it has to
     *  time out to discover), then halts the read loop, stops all sessions,
     *  and closes the socket. Idempotent and safe to call from a signal
     *  handler posted onto the event loop.
     */
    void stop() override
    {
        if (halt_)
            return;

        reap_timer_.cancel();

        // Before halt_ and link_->stop(), both of which make send_to() refuse
        // every datagram: these notifications have to reach the wire.
        // Built once, not once per session: the callee takes const references.
        const std::string reason("server shutdown");
        const std::string client_reason;
        for (auto &[addr, entry] : sessions_)
        {
            entry.recv->set_disconnect_cause(DisconnectCause::SERVER_SHUTDOWN);
            entry.recv->push_halt_restart_msg(HaltRestart::RESTART, reason, client_reason);
        }

        halt_ = true;
        if (link_)
            link_->stop();

        for (auto &[addr, entry] : sessions_)
        {
            entry.recv->stop();
            entry.send->stop();
        }
        sessions_.clear();
        peer_ids_.clear();

        openvpn_io::error_code ec;
        socket_.close(ec);

        OPENVPN_LOG("UDP server stopped");
    }

    /**
     * @brief Describe the bound local endpoint.
     * @return A string of the form @c "<addr>:<port>".
     */
    std::string local_endpoint_info() const override
    {
        std::ostringstream os;
        os << local_.address().to_string() << ':' << local_.port();
        return os.str();
    }

    /**
     * @brief The bound local address.
     * @return The address the listener is bound to.
     */
    IP::Addr local_endpoint_addr() const override
    {
        return IP::Addr::from_asio(local_.address());
    }

    /**
     * @brief The listening socket's native OS descriptor.
     * @details Every session shares this one socket (the kernel demuxes by
     *  remote endpoint, not by fd) -- so a DCO backend's @c new_peer() calls
     *  all pass this same handle, unlike a client's 1:1 socket-per-connection
     *  model. Only valid after @c start().
     * @return The socket's native handle.
     */
    openvpn_io::ip::udp::socket::native_handle_type native_handle()
    {
        return socket_.native_handle();
    }

    /**
     * @brief Number of sessions currently in the table.
     * @return The live session count.
     */
    size_t n_clients() const
    {
        return sessions_.size();
    }

    /**
     * @brief Write a datagram to a client endpoint.
     * @param buf The packet to send.
     * @param endpoint The destination.
     * @return True if the datagram was written in full.
     */
    bool send_to(const Buffer &buf, const AsioEndpoint &endpoint)
    {
        if (halt_ || !link_)
            return false;
        return link_->send(buf, &endpoint) == 0;
    }

  private:
    using LinkImpl = UDPTransport::UDPLink<Server *>;

    /**
     * @brief Adapter letting the cookie component send its reply over our socket.
     */
    class CookieTransport : public PsidCookieTransportBase
    {
      public:
        /**
         * @brief Bind the adapter to its server.
         * @param server The owning server. Borrowed; outlives this object.
         */
        explicit CookieTransport(Server *server)
            : server_(server)
        {
        }

        /**
         * @brief Send a psid cookie reply to the client that prompted it.
         * @param send_buf The reply packet built by the cookie component.
         * @param pcaib Address info for the client, carrying the endpoint in
         *  its implementation-specific field.
         * @return True if the reply was sent in full.
         */
        bool psid_cookie_send_const(Buffer &send_buf,
                                    const PsidCookieAddrInfoBase &pcaib) override
        {
            const auto *ep = static_cast<const AsioEndpoint *>(pcaib.get_impl_info());
            return ep && server_->send_to(send_buf, *ep);
        }

      private:
        Server *server_;
    };

    /**
     * @brief Handle one received datagram.
     * @details Demuxes to an existing session by source endpoint, or runs the
     *  two stateless gates and creates a session. The buffer is consumed within
     *  this call; @c UDPLink reuses the packet object afterwards.
     * @param pfp The received packet and its source endpoint.
     */
    void udp_read_handler(UDPTransport::PacketFrom::SPtr &pfp)
    {
        if (halt_)
            return;

        const AsioEndpoint &from = pfp->sender_endpoint;
        const size_t bytes = pfp->buf.size();

        if (const auto it = sessions_.find(from); it != sessions_.end())
        {
            auto &entry = it->second;
            entry.send->count_in(bytes);
            entry.recv->transport_recv(pfp->buf);

            // transport_recv() can tear the session down and erase this entry,
            // so re-find rather than reuse it/entry.
            const auto after = sessions_.find(from);
            if (after != sessions_.end() && !after->second.recv->defined())
                remove_session(after);
            return;
        }

        // Unknown source, but possibly an existing client whose NAT mapping
        // changed mid-session (peer float) rather than a new connection
        // attempt: if the packet carries a DATA_V2 peer id matching a known
        // session, try that session before treating this as unauthenticated.
        // transport_recv()'s return value is the actual proof -- it is only
        // true if the packet decrypted and authenticated against that
        // session's real key (see extract_peer_id_hint()'s doc comment for
        // why a wrong or spoofed guess here is harmless). Only on that proof
        // do we move the session to the new endpoint and notify the float;
        // otherwise fall through to the normal new-connection gates below,
        // since a failed match here is equally consistent with an unrelated
        // new client.
        if (const auto peer_id = extract_peer_id_hint(pfp->buf))
        {
            const AsioEndpoint *known = peer_ids_.find(*peer_id);
            if (known && *known != from)
            {
                const auto sit = sessions_.find(*known);
                if (sit != sessions_.end())
                {
                    auto &entry = sit->second;
                    const bool authenticated = entry.recv->transport_recv(pfp->buf);
                    if (!entry.recv->defined())
                    {
                        remove_session(sit);
                        return;
                    }
                    if (authenticated)
                    {
                        entry.send->count_in(bytes);
                        float_session(sit, from);
                        return;
                    }
                }
            }
        }

        // Unknown source: no per-client state exists yet and none is created
        // until a stateless gate passes.
        //
        // The cookie runs first. Both packets of the cookie exchange arrive
        // from an endpoint with no session, and only the first of them is a
        // HARD_RESET; validate_initial_packet() accepts nothing else, so
        // prevalidating here would reject every cookie ACK and no client could
        // ever connect. The cookie does its own HMAC check on both packets, so
        // prevalidation adds nothing on this path anyway.
        const ClientAddrInfo pcaib(from);
        const PsidCookie::Intercept rc = psid_cookie_->intercept(pfp->buf, pcaib);
        switch (rc)
        {
        case PsidCookie::Intercept::HANDLE_2ND:
            // Cookie verified: the client proved it owns its source address.
            new_session(from, psid_cookie_->get_cookie_psid(), pfp->buf, bytes);
            break;

        case PsidCookie::Intercept::DECLINE_HANDLING:
            // No cookie-capable gate is configured (plain tls-crypt v1, or
            // neither tls-auth nor tls-crypt), so this is the client's first
            // packet and prevalidation is the only pre-TLS filter available.
            // There is no proof of address ownership on this path.
            //
            // With neither tls-auth nor tls-crypt, validate_initial_packet()
            // has no prevalidator to consult and returns true unconditionally
            // (servproto.hpp), so without this shape check any datagram at all
            // -- including the empty buffer a failed peer-float attempt leaves
            // behind -- would allocate a session and an SSL context. Requiring
            // the opcode a client's first packet must carry is not address
            // proof, but it is the difference between one forged byte and a
            // well-formed handshake opener.
            if (looks_like_client_reset(pfp->buf)
                && proto_factory_->validate_initial_packet(pfp->buf))
                new_session(from, ProtoSessionID(), pfp->buf, bytes);
            break;

        case PsidCookie::Intercept::HANDLE_1ST:
            // Cookie reply sent statelessly; nothing to retain.
            break;

        default:
            // EARLY_DROP, DROP_1ST, DROP_2ND.
            break;
        }
    }

    /**
     * @brief Create a session for a newly validated client and feed it the packet.
     * @param from The client's source endpoint, which keys the session table.
     * @param cookie_psid Server session ID recovered from the cookie, or a
     *  default-constructed ID when the cookie gate was declined.
     * @param buf The packet that triggered creation, delivered after start.
     * @param bytes Size of that packet, for the client's byte counters.
     */
    void new_session(const AsioEndpoint &from,
                     const ProtoSessionID &cookie_psid,
                     BufferAllocated &buf,
                     const size_t bytes)
    {
        if (sessions_.size() >= config_->max_clients)
        {
            OPENVPN_LOG("UDP server: max_clients reached, dropping " << from);
            return;
        }

        Entry entry;
        entry.recv = proto_factory_->new_client_instance();
        entry.send.reset(new PeerSend(this, from));

        auto res = sessions_.emplace(from, entry);
        if (!res.second)
            return;

        PeerAddr::Ptr peer_addr(new PeerAddr());
        peer_addr->tcp = false;
        peer_addr->remote.addr = IP::Addr::from_asio(from.address());
        peer_addr->remote.port = from.port();
        peer_addr->local.addr = IP::Addr::from_asio(local_.address());
        peer_addr->local.port = local_.port();

        const auto peer_id_slot = peer_ids_.acquire(from);
        if (!peer_id_slot)
        {
            OPENVPN_LOG("UDP server: no free peer id, dropping " << from);
            sessions_.erase(res.first);
            return;
        }
        const int peer_id = *peer_id_slot;
        entry.recv->start(entry.send, peer_addr, peer_id, cookie_psid);
        entry.send->count_in(bytes);
        entry.recv->transport_recv(buf);

        if (!entry.recv->defined())
        {
            auto it = sessions_.find(from);
            if (it != sessions_.end())
                remove_session(it);
            return;
        }

        res.first->second.peer_id = peer_id;
    }

    /**
     * @brief One session-table entry: the protocol session, its sender, and
     *  the peer id assigned at connect time (used to recognize a float).
     */
    struct Entry
    {
        TransportClientInstance::Recv::Ptr recv;
        PeerSend::Ptr send;
        int peer_id = -1;
    };

    using SessionMap = std::map<AsioEndpoint, Entry>;

    /**
     * @brief Stop and erase one session.
     * @param it Iterator into the session table. Invalidated on return.
     */
    void remove_session(SessionMap::iterator it)
    {
        it->second.recv->stop();
        it->second.send->stop();
        peer_ids_.release(it->second.peer_id);
        sessions_.erase(it);
    }

    /**
     * @brief Migrate a session already proven to own this packet to its new
     *  source endpoint.
     * @details Called only after the candidate session's own @c transport_recv()
     *  has successfully decrypted and authenticated the packet from the new
     *  endpoint -- that is the proof this is a legitimate float, not spoofing.
     * @param it Iterator into the session table, keyed by the *old* endpoint.
     *  Invalidated on return.
     * @param new_endpoint The client's new source address and port.
     */
    void float_session(SessionMap::iterator it, const AsioEndpoint &new_endpoint)
    {
        Entry entry = std::move(it->second);
        const AsioEndpoint old_endpoint = it->first;
        sessions_.erase(it);

        entry.send->set_endpoint(new_endpoint);
        peer_ids_.update(entry.peer_id, new_endpoint);

        PeerAddr::Ptr peer_addr(new PeerAddr());
        peer_addr->tcp = false;
        peer_addr->remote.addr = IP::Addr::from_asio(new_endpoint.address());
        peer_addr->remote.port = new_endpoint.port();
        peer_addr->local.addr = IP::Addr::from_asio(local_.address());
        peer_addr->local.port = local_.port();

        OPENVPN_LOG("UDP server: peer " << entry.peer_id << " floated from "
                                        << old_endpoint << " to " << new_endpoint);
        entry.recv->float_notify(peer_addr);

        sessions_.emplace(new_endpoint, std::move(entry));
    }

    /**
     * @brief Arm the periodic sweep that reaps ended sessions.
     * @details A session that ends without a further inbound packet (keepalive
     *  timeout, or a server-side disconnect) leaves no event to notice it, so
     *  the table is swept rather than relying solely on the receive path.
     */
    void schedule_reap()
    {
        if (halt_)
            return;
        reap_timer_.expires_after(Time::Duration::seconds(config_->reap_interval));
        reap_timer_.async_wait([self = Ptr(this)](const openvpn_io::error_code &error)
                               {
                                   if (!error)
                                       self->reap(); });
    }

    /**
     * @brief Erase every session that has ended, then re-arm the sweep.
     */
    void reap()
    {
        if (halt_)
            return;
        for (auto it = sessions_.begin(); it != sessions_.end();)
        {
            if (!it->second.recv->defined())
            {
                it->second.recv->stop();
                it->second.send->stop();
                peer_ids_.release(it->second.peer_id);
                it = sessions_.erase(it);
            }
            else
                ++it;
        }
        schedule_reap();
    }

    openvpn_io::io_context &io_context_;
    Config::Ptr config_;
    ServerProto::Factory::Ptr proto_factory_;
    openvpn_io::ip::udp::socket socket_;
    AsioEndpoint local_;
    LinkImpl::Ptr link_;
    PsidCookie::Ptr psid_cookie_;
    SessionMap sessions_;
    AsioTimer reap_timer_;
    PeerId::Table<AsioEndpoint> peer_ids_{0};
    bool started_ = false;
    bool halt_ = false;
};

inline PeerSend::PeerSend(Server *server, const AsioEndpoint &endpoint)
    : server_(server), endpoint_(endpoint)
{
    std::ostringstream os;
    os << "UDP " << endpoint_.address().to_string() << ':' << endpoint_.port();
    info_ = os.str();
}

inline bool PeerSend::transport_send_const(const Buffer &buf)
{
    if (halt_ || !server_)
        return false;
    const size_t size = buf.size();
    if (!server_->send_to(buf, endpoint_))
        return false;
    stats_.tx_bytes += size;
    return true;
}

} // namespace openvpn::UDPTransportServer

#endif
