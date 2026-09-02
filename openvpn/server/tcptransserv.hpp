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
 * @brief A userspace TCP transport server: listener, per-connection sessions.
 *
 * @details
 * Implements the @c TransportServer and @c TransportClientInstance::Send seams
 * (`openvpn/transport/server/transbase.hpp`) over a listening TCP socket, using
 * the existing @c TCPTransport::TCPLink for the read loop, the 16-bit length
 * framing, and the send queue.
 *
 * This is the sibling of @c udptransserv.hpp, and the differences are all
 * consequences of TCP being connection-oriented rather than a shared datagram
 * socket:
 *
 * **A session belongs to a connection, not to an address.** The UDP server
 * demuxes every datagram by source endpoint and carries peer-float machinery so
 * a client whose NAT mapping changes mid-session is not stranded. Here the
 * accepted socket *is* the session's identity, so the table is keyed by
 * connection id, and float has no meaning: a client that reconnects from a new
 * address opens a new connection, which is a new session.
 *
 * **No psid cookie.** The stateless HMAC cookie exists because a UDP source
 * address is trivially spoofable and no per-client state may be allocated
 * before the client proves it can receive at the address it claims. TCP's own
 * handshake already establishes that, so the cookie would buy nothing. What TCP
 * needs instead is protection against a peer that completes the handshake and
 * then does nothing, or opens connections in bulk: hence @c handshake_timeout,
 * @c max_conns_per_addr and @c max_clients, all enforced on the accept side
 * before a session exists. @c validate_initial_packet() remains the pre-TLS
 * filter on the first packet, as it is on the UDP server's declined-cookie
 * path.
 *
 * **Sends can block.** A datagram send either happens or is dropped, so the UDP
 * peer sender needs no queue. A TCP peer that stops reading will otherwise grow
 * one without bound, so @c TCPLink is given @c Config::send_queue_max_packets
 * and reports @c TCP_OVERFLOW through @c tcp_error_handler() when a client
 * exceeds it; that closes the connection rather than consuming memory on its
 * behalf.
 *
 * **Not a kernel DCO path.** DCO offload is a datagram concept here: the
 * handoff in `openvpn/server_api/openvpn_server.hpp` passes a UDP socket fd to
 * the kernel module. A TCP listener has no equivalent, so a TCP server always
 * runs the classic userspace data path. This matches how the mainline `ovpn`
 * module structures it and is stated in `_planning/o3-server/` §5.7.
 *
 * Deviation from RFC §5.7 worth recording: that section names
 * @c Acceptor::TCP / @c AsioPolySock as the listener. This uses a plain
 * @c openvpn_io::ip::tcp::acceptor instead, because @c TCPLink takes a
 * @c Protocol::socket& and reaching the socket inside an @c AsioPolySock::Base
 * requires a downcast, while @c udptransserv.hpp likewise uses a raw asio
 * socket. The @c Acceptor machinery earns its keep for the SSL-mode and
 * alt-routing cases this server does not have; port-share or TLS-link support
 * would be the reason to revisit.
 *
 * Single-threaded, like its UDP sibling: every method must run on the owning
 * @c io_context's thread.
 */

#ifndef OPENVPN_SERVER_TCPTRANSSERV_H
#define OPENVPN_SERVER_TCPTRANSSERV_H

#include <cstdint>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

#include <openvpn/io/io.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/logger.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/server/peeraddr.hpp>
#include <openvpn/server/peerid.hpp>
#include <openvpn/server/peerstats.hpp>
#include <openvpn/server/servhalt.hpp>
#include <openvpn/server/servproto.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/transport/tcplink.hpp>
#include <openvpn/transport/server/transbase.hpp>

namespace openvpn::TCPTransportServer {

using AsioEndpoint = openvpn_io::ip::tcp::endpoint;

/** @brief Listener configuration for @c Server. */
struct Config : public RC<thread_unsafe_refcount>
{
    using Ptr = RCPtr<Config>;

    /** Local address to bind. Use @c "0.0.0.0" or @c "::" to accept on any. */
    std::string bind_addr = "0.0.0.0";

    /** Local TCP port to listen on. */
    unsigned short port = 1194;

    /** Frame geometry, supplying buffer headroom and capacity. Required. */
    Frame::Ptr frame;

    /** Server-wide statistics sink. Required. */
    SessionStats::Ptr stats;

    /** Upper bound on concurrent sessions; further connections are refused. */
    size_t max_clients = 1024;

    /**
     * Seconds a connection may stay open without producing a packet that
     * passes @c validate_initial_packet().
     * @details The accept-side counterpart to the UDP server's psid cookie: it
     *  bounds what a peer can hold open by completing the TCP handshake and
     *  then stalling. 0 disables the timeout, which is not advisable on a
     *  reachable listener.
     */
    unsigned int handshake_timeout = 30;

    /**
     * Concurrent connections permitted from one source address, or 0 for no
     * limit. Bounds bulk connection attempts from a single peer.
     */
    size_t max_conns_per_addr = 8;

    /**
     * Outbound packets that may sit queued for one connection before it is
     * dropped, or 0 to disable the limit.
     * @details A count of queued packets, not a byte total: @c TCPLink's
     *  @c send_queue_size() returns @c queue.size(), and it raises
     *  @c TCP_OVERFLOW once this many are outstanding. At a ~1500-byte MTU the
     *  default bounds a stalled client at roughly 1.5 MB of buffered data.
     *  A client that stops reading must not be able to grow the server's
     *  memory use without bound.
     */
    size_t send_queue_max_packets = 1024;

    /** Per-connection buffer free-list bound, passed to @c TCPLink. */
    size_t free_list_max_size = 8;

    /** Seconds between sweeps that reap sessions which ended without a packet. */
    unsigned int reap_interval = 5;
};

class Server;

/**
 * @brief One accepted connection: owns the socket and link, and is the
 *  per-client sender.
 *
 * @details
 * Plays three roles for a single client, which is why they share an object: it
 * owns the accepted socket, it is the @c TCPLink's read handler, and it is the
 * @c TransportClientInstance::Send handed to the protocol session.
 *
 * Holds only a raw pointer to the server, which outlives every connection;
 * @c stop() clears it so a late send cannot reach a destroyed server. Session
 * dispatch deliberately lives in @c Server rather than here, so the table and
 * the admission rules stay in one place, exactly as the UDP server keeps them
 * in @c udp_read_handler().
 */
class Connection : public TransportClientInstance::Send
{
  public:
    using Ptr = RCPtr<Connection>;
    using LinkImpl = TCPTransport::TCPLink<openvpn_io::ip::tcp, Connection *, false>;

    friend LinkImpl::Base; // calls tcp_read_handler and friends

    /**
     * @brief Construct an idle connection, before the socket is accepted into it.
     * @param server The owning server. Borrowed, not owned.
     * @param io_context Event loop the socket and timeout timer attach to.
     * @param id Identity of this connection within the server's table.
     */
    Connection(Server *server, openvpn_io::io_context &io_context, const std::uint64_t id)
        : server_(server),
          socket_(io_context),
          timeout_timer_(io_context),
          id_(id)
    {
    }

    /**
     * @brief The socket the acceptor should accept into.
     * @return Mutable reference to this connection's socket.
     */
    openvpn_io::ip::tcp::socket &socket()
    {
        return socket_;
    }

    /**
     * @brief Begin reading from an accepted socket.
     * @details Records the peer endpoint for logging and admission accounting,
     *  builds the link, and arms the handshake timeout.
     * @param config Listener configuration, supplying frame, stats and limits.
     */
    void start(const Config &config)
    {
        openvpn_io::error_code ec;
        remote_ = socket_.remote_endpoint(ec);
        if (!ec)
            local_ = socket_.local_endpoint(ec);

        std::ostringstream os;
        os << "TCP " << remote_.address().to_string() << ':' << remote_.port();
        info_ = os.str();

        socket_.set_option(openvpn_io::ip::tcp::no_delay(true), ec);

        link_.reset(new LinkImpl(this,
                                 socket_,
                                 config.send_queue_max_packets,
                                 config.free_list_max_size,
                                 (*config.frame)[Frame::READ_LINK_TCP],
                                 config.stats));
        link_->start();

        arm_handshake_timeout(config.handshake_timeout);
    }

    /**
     * @brief Report whether this sender can still transmit.
     * @return True until @c stop() is called.
     */
    bool defined() const override
    {
        return !halt_;
    }

    /**
     * @brief Halt the connection, close its socket, and drop its server link.
     * @details Idempotent, and safe to call from a link error callback.
     */
    void stop() override
    {
        if (halt_)
            return;
        halt_ = true;
        server_ = nullptr;

        timeout_timer_.cancel();
        if (link_)
            link_->stop();

        openvpn_io::error_code ec;
        socket_.close(ec);
    }

    /**
     * @brief Send a const packet to this client.
     * @param buf The encapsulated packet to transmit.
     * @return True if the packet was queued for transmission.
     */
    bool transport_send_const(const Buffer &buf) override
    {
        if (halt_ || !link_)
            return false;
        BufferAllocated copy(buf);
        return send_buffer(copy);
    }

    /**
     * @brief Send a mutable packet to this client.
     * @param buf The encapsulated packet to transmit. May be consumed.
     * @return True if the packet was queued for transmission.
     */
    bool transport_send(BufferAllocated &buf) override
    {
        if (halt_ || !link_)
            return false;
        return send_buffer(buf);
    }

    /**
     * @brief Human-readable description of this client's transport, for logging.
     * @return A string of the form @c "TCP <addr>:<port>".
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
     * @brief Account for a received packet.
     * @param bytes Size of the packet in bytes.
     */
    void count_in(const size_t bytes)
    {
        stats_.rx_bytes += bytes;
    }

    /**
     * @brief Note that the session for this connection is established.
     * @details Cancels the handshake timeout: the connection has proven itself
     *  and is now governed by the protocol layer's own keepalive.
     */
    void handshake_complete()
    {
        handshake_done_ = true;
        timeout_timer_.cancel();
    }

    /** @brief The peer's address and port. */
    const AsioEndpoint &remote() const
    {
        return remote_;
    }

    /** @brief The local address and port this connection was accepted on. */
    const AsioEndpoint &local() const
    {
        return local_;
    }

    /** @brief This connection's identity within the server's table. */
    std::uint64_t id() const
    {
        return id_;
    }

  private:
    /**
     * @brief Queue one packet on the link and account for it.
     * @param buf Packet to send. May be consumed by the link.
     * @return True if the link accepted it.
     */
    bool send_buffer(BufferAllocated &buf)
    {
        const size_t bytes = buf.size();
        if (!link_->send(buf))
            return false;
        stats_.tx_bytes += bytes;
        return true;
    }

    /**
     * @brief Drop the connection if it produces no valid first packet in time.
     * @param seconds Timeout in seconds; 0 disables the timer.
     */
    void arm_handshake_timeout(const unsigned int seconds);

    /**
     * @brief Deliver one framed packet to the server for session dispatch.
     * @details Called by @c TCPLink once per complete packet.
     * @param buf The de-framed packet.
     * @return True to continue reading from this connection.
     */
    bool tcp_read_handler(BufferAllocated &buf);

    /** @brief Handle orderly close by the peer. */
    void tcp_eof_handler();

    /**
     * @brief Handle a link-level failure, including send-queue overflow.
     * @param error Short reason string from @c TCPLink.
     */
    void tcp_error_handler(const char *error);

    /** @brief Link callback indicating queued data is ready to write. */
    void tcp_write_queue_needs_send()
    {
    }

    Server *server_;
    openvpn_io::ip::tcp::socket socket_;
    AsioTimer timeout_timer_;
    LinkImpl::Ptr link_;
    AsioEndpoint remote_;
    AsioEndpoint local_;
    std::string info_;
    PeerStats stats_;
    PeerStats polled_;
    const std::uint64_t id_;
    bool halt_ = false;
    bool handshake_done_ = false;
};

/**
 * @brief TCP listener owning the acceptor, the connection table, and admission.
 *
 * @details
 * Single-threaded: every method must run on the owning @c io_context's thread.
 * Each table entry owns both the protocol session and its @c Connection; the
 * connection holds only a raw pointer back, so no ownership cycle exists.
 */
class Server : public TransportServer
{
    friend class Connection;

  public:
    using Ptr = RCPtr<Server>;

    /**
     * @brief Construct the server.
     * @param io_context Event loop the acceptor and timers attach to.
     * @param config Listener configuration. Must carry a frame and a stats sink.
     * @param proto_factory Protocol factory producing per-client sessions; also
     *  supplies the prevalidation gate.
     * @throws openvpn::Exception if the configuration is incomplete.
     */
    Server(openvpn_io::io_context &io_context,
           Config::Ptr config,
           ServerProto::Factory::Ptr proto_factory)
        : io_context_(io_context),
          config_(std::move(config)),
          proto_factory_(std::move(proto_factory)),
          acceptor_(io_context),
          reap_timer_(io_context)
    {
        if (!config_ || !config_->frame || !config_->stats)
            throw Exception("TCPTransportServer: config requires frame and stats");
        if (!proto_factory_)
            throw Exception("TCPTransportServer: proto factory required");

        peer_ids_ = PeerId::Table<std::uint64_t>(config_->max_clients);
    }

    /**
     * @brief Open the listening socket, begin accepting, and arm the reaper.
     * @details Idempotent.
     * @throws openvpn_io::system_error if the socket cannot be opened, bound
     *  or listened on.
     */
    void start() override
    {
        if (started_)
            return;
        started_ = true;

        const IP::Addr bind_ip = IP::Addr::from_string(config_->bind_addr, "bind_addr");
        const AsioEndpoint local(bind_ip.to_asio(), config_->port);

        acceptor_.open(local.protocol());
        acceptor_.set_option(openvpn_io::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(local);
        acceptor_.listen();
        local_ = acceptor_.local_endpoint();

        OPENVPN_LOG("TCP server listening on " << local_endpoint_info());
        queue_accept();
        schedule_reap();
    }

    /**
     * @brief Stop accepting and tear down every session.
     * @details Notifies every connected client with a RESTART before halting,
     *  matching the UDP server's graceful-shutdown behaviour so a clean stop
     *  reads as an expected disconnect rather than a network failure the client
     *  has to time out. Idempotent.
     */
    void stop() override
    {
        if (halt_)
            return;

        reap_timer_.cancel();

        // Before halt_, which makes every send refuse: these notifications
        // have to reach the wire.
        const std::string reason("server shutdown");
        const std::string client_reason;
        for (auto &[id, entry] : connections_)
        {
            if (entry.recv)
            {
                entry.recv->set_disconnect_cause(DisconnectCause::SERVER_SHUTDOWN);
                entry.recv->push_halt_restart_msg(HaltRestart::RESTART, reason, client_reason);
            }
        }

        halt_ = true;

        openvpn_io::error_code ec;
        acceptor_.close(ec);

        for (auto &[id, entry] : connections_)
        {
            if (entry.recv)
                entry.recv->stop();
            entry.conn->stop();
        }
        connections_.clear();
        conns_per_addr_.clear();
        peer_ids_.clear();

        OPENVPN_LOG("TCP server stopped");
    }

    /**
     * @brief Describe the listening endpoint.
     * @return A string of the form @c "<addr>:<port>".
     */
    std::string local_endpoint_info() const override
    {
        std::ostringstream os;
        os << local_.address().to_string() << ':' << local_.port();
        return os.str();
    }

    /**
     * @brief The address the listener is bound to.
     * @return The local address.
     */
    IP::Addr local_endpoint_addr() const override
    {
        return IP::Addr::from_asio(local_.address());
    }

    /**
     * @brief Number of live sessions.
     * @return Count of entries in the connection table.
     */
    size_t n_clients() const
    {
        return connections_.size();
    }

  private:
    /**
     * @brief One table entry: the protocol session and its connection.
     * @details @c recv is null between accept and a validated first packet,
     *  which is the window @c Config::handshake_timeout bounds.
     */
    struct Entry
    {
        TransportClientInstance::Recv::Ptr recv;
        Connection::Ptr conn;
        int peer_id = -1;
    };

    using ConnMap = std::map<std::uint64_t, Entry>;

    /** @brief Post an asynchronous accept for the next inbound connection. */
    void queue_accept()
    {
        if (halt_)
            return;

        Connection::Ptr conn(new Connection(this, io_context_, next_conn_id_++));
        auto &sock = conn->socket();
        acceptor_.async_accept(sock,
                               [self = Ptr(this), conn](const openvpn_io::error_code &error)
                               {
                                   self->handle_accept(conn, error);
                               });
    }

    /**
     * @brief Admit or refuse a newly accepted connection, then queue the next.
     * @param conn The connection the socket was accepted into.
     * @param error Result of the accept.
     */
    void handle_accept(const Connection::Ptr &conn, const openvpn_io::error_code &error)
    {
        if (halt_)
            return;

        if (error)
        {
            // A failed accept must not silently end the accept loop.
            if (error != openvpn_io::error::operation_aborted)
            {
                OPENVPN_LOG("TCP server: accept error: " << error.message());
                queue_accept();
            }
            return;
        }

        openvpn_io::error_code ec;
        const AsioEndpoint remote = conn->socket().remote_endpoint(ec);
        if (ec)
        {
            // Peer vanished between accept and getpeername; nothing to admit.
            conn->stop();
            queue_accept();
            return;
        }

        if (connections_.size() >= config_->max_clients)
        {
            OPENVPN_LOG("TCP server: max_clients reached, refusing " << remote);
            conn->stop();
            queue_accept();
            return;
        }

        const IP::Addr addr = IP::Addr::from_asio(remote.address());
        if (config_->max_conns_per_addr)
        {
            const auto it = conns_per_addr_.find(addr);
            if (it != conns_per_addr_.end() && it->second >= config_->max_conns_per_addr)
            {
                OPENVPN_LOG("TCP server: per-address connection limit reached, refusing " << remote);
                conn->stop();
                queue_accept();
                return;
            }
        }

        Entry entry;
        entry.conn = conn;
        connections_.emplace(conn->id(), entry);
        ++conns_per_addr_[addr];

        conn->start(*config_);
        queue_accept();
    }

    /**
     * @brief Dispatch one packet from a connection to its session.
     * @details Before a session exists this is the client's first packet, and
     *  @c validate_initial_packet() is the pre-TLS gate that must pass before
     *  any per-client state is allocated. Afterwards packets go straight to the
     *  session.
     * @param id Connection the packet arrived on.
     * @param buf The de-framed packet.
     * @return True to continue reading from that connection.
     */
    bool on_packet(const std::uint64_t id, BufferAllocated &buf)
    {
        if (halt_)
            return false;

        const auto it = connections_.find(id);
        if (it == connections_.end())
            return false;

        Entry &entry = it->second;
        const size_t bytes = buf.size();

        if (!entry.recv)
        {
            if (!proto_factory_->validate_initial_packet(buf))
            {
                OPENVPN_LOG("TCP server: first packet failed prevalidation from "
                            << entry.conn->transport_info());
                remove_connection(it);
                return false;
            }
            if (!new_session(entry))
            {
                remove_connection(it);
                return false;
            }
        }

        entry.conn->count_in(bytes);
        entry.recv->transport_recv(buf);

        // transport_recv() flushes the control channel, and a send that fills
        // the queue reports TCP_OVERFLOW synchronously through
        // tcp_error_handler(), which erases this entry. Re-find rather than
        // reuse it/entry, both of which that path invalidates.
        const auto after = connections_.find(id);
        if (after == connections_.end())
            return false;
        if (!after->second.recv->defined())
        {
            remove_connection(after);
            return false;
        }
        return true;
    }

    /**
     * @brief Create the protocol session for an admitted connection.
     * @param entry Table entry whose @c recv is still null.
     * @return True if the session started.
     */
    bool new_session(Entry &entry)
    {
        entry.recv = proto_factory_->new_client_instance();
        if (!entry.recv)
            return false;

        PeerAddr::Ptr peer_addr(new PeerAddr());
        peer_addr->tcp = true;
        peer_addr->remote.addr = IP::Addr::from_asio(entry.conn->remote().address());
        peer_addr->remote.port = entry.conn->remote().port();
        peer_addr->local.addr = IP::Addr::from_asio(entry.conn->local().address());
        peer_addr->local.port = entry.conn->local().port();

        const auto peer_id_slot = peer_ids_.acquire(entry.conn->id());
        if (!peer_id_slot)
        {
            OPENVPN_LOG("TCP server: no free peer id for " << entry.conn->transport_info());
            return false;
        }
        entry.peer_id = *peer_id_slot;
        // No cookie on this path, so no server session id to carry over.
        entry.recv->start(entry.conn, peer_addr, entry.peer_id);
        entry.conn->handshake_complete();
        return true;
    }

    /**
     * @brief Handle a connection reporting EOF or a link error.
     * @param id Connection reporting the condition.
     */
    void connection_closed(const std::uint64_t id)
    {
        if (halt_)
            return;
        const auto it = connections_.find(id);
        if (it != connections_.end())
            remove_connection(it);
    }

    /**
     * @brief Stop and erase one connection and its session.
     * @param it Iterator into the connection table. Invalidated on return.
     */
    void remove_connection(ConnMap::iterator it)
    {
        const Entry entry = std::move(it->second);

        const IP::Addr addr = IP::Addr::from_asio(entry.conn->remote().address());
        const auto ait = conns_per_addr_.find(addr);
        if (ait != conns_per_addr_.end() && --ait->second == 0)
            conns_per_addr_.erase(ait);

        connections_.erase(it);

        if (entry.recv)
            entry.recv->stop();
        peer_ids_.release(entry.peer_id);
        entry.conn->stop();

        // The usual caller is on_packet(), reached from the connection's own
        // TCPLink read callback: dropping the last reference here would destroy
        // that link while it is still executing. Holding the entry in a posted
        // continuation defers destruction until the current handler returns.
        openvpn_io::post(io_context_, [entry]() {});
    }

    /** @brief Arm the periodic sweep for sessions that ended without a packet. */
    void schedule_reap()
    {
        if (halt_ || !config_->reap_interval)
            return;
        reap_timer_.expires_after(Time::Duration::seconds(config_->reap_interval));
        reap_timer_.async_wait([self = Ptr(this)](const openvpn_io::error_code &error)
                               {
                                   if (!error)
                                       self->reap(); });
    }

    /**
     * @brief Erase sessions whose protocol instance has stopped.
     * @details A session can end without another packet arriving on its
     *  connection -- an auth failure or a keepalive timeout, say -- so nothing
     *  would otherwise notice it is finished.
     */
    void reap()
    {
        if (halt_)
            return;

        for (auto it = connections_.begin(); it != connections_.end();)
        {
            const Entry &entry = it->second;
            const bool dead = (entry.recv && !entry.recv->defined())
                              || !entry.conn->defined();
            if (dead)
            {
                const auto next = std::next(it);
                remove_connection(it);
                it = next;
            }
            else
                ++it;
        }
        schedule_reap();
    }

    openvpn_io::io_context &io_context_;
    Config::Ptr config_;
    ServerProto::Factory::Ptr proto_factory_;
    openvpn_io::ip::tcp::acceptor acceptor_;
    AsioTimer reap_timer_;
    AsioEndpoint local_;
    ConnMap connections_;
    std::map<IP::Addr, size_t> conns_per_addr_;
    std::uint64_t next_conn_id_ = 1;
    PeerId::Table<std::uint64_t> peer_ids_{0};
    bool started_ = false;
    bool halt_ = false;
};

// Connection methods needing Server's definition.

inline void Connection::arm_handshake_timeout(const unsigned int seconds)
{
    if (!seconds)
        return;
    timeout_timer_.expires_after(Time::Duration::seconds(seconds));
    timeout_timer_.async_wait([self = Ptr(this)](const openvpn_io::error_code &error)
                              {
                                  if (error || self->handshake_done_ || self->halt_)
                                      return;
                                  Server *server = self->server_;
                                  OPENVPN_LOG("TCP server: handshake timeout on " << self->info_);
                                  if (server)
                                      server->connection_closed(self->id_);
                                  else
                                      self->stop(); });
}

inline bool Connection::tcp_read_handler(BufferAllocated &buf)
{
    if (halt_ || !server_)
        return false;
    return server_->on_packet(id_, buf);
}

inline void Connection::tcp_eof_handler()
{
    Server *server = server_;
    if (server)
        server->connection_closed(id_);
    else
        stop();
}

inline void Connection::tcp_error_handler(const char *error)
{
    OPENVPN_LOG("TCP server: " << (error ? error : "link error") << " on " << info_);
    Server *server = server_;
    if (server)
        server->connection_closed(id_);
    else
        stop();
}

} // namespace openvpn::TCPTransportServer

#endif
