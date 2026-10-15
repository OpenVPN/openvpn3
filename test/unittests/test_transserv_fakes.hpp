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
 * @brief Fake protocol sessions and factory for driving the UDP and TCP
 *  transport servers over loopback without a TLS handshake.
 */

#ifndef OPENVPN_TEST_TRANSSERV_FAKES_H
#define OPENVPN_TEST_TRANSSERV_FAKES_H

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <openvpn/io/io.hpp>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/crypto/cryptodc.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/server/peeraddr.hpp>
#include <openvpn/server/peerstats.hpp>
#include <openvpn/server/servhalt.hpp>
#include <openvpn/server/servproto.hpp>
#include <openvpn/ssl/datalimit.hpp>
#include <openvpn/ssl/psid.hpp>
#include <openvpn/transport/server/transbase.hpp>
#include <openvpn/tun/server/tunbase.hpp>

namespace openvpn::test {

/** @brief First byte of a client's opening HARD_RESET_CLIENT_V2: opcode 7, key id 0. */
inline constexpr std::uint8_t client_reset_opcode = 7U << 3U;

/** @brief A client's opening hard reset, padded to a 4-byte header. */
inline constexpr std::array<std::uint8_t, 4> client_reset_packet = {client_reset_opcode, 0, 0, 0};

/**
 * @brief Scriptable stand-in for a protocol session that records what the
 *  transport server does to it.
 */
class FakeSession : public TransportClientInstance::Recv
{
  public:
    using Ptr = RCPtr<FakeSession>;

    /** @brief End the session inside the first @c transport_recv(), as a failed handshake would. */
    bool die_on_first_recv = false;

    /** @brief Packets @c push_halt_restart_msg() sends to the client. */
    int halt_msg_packets = 1;

    bool started = false;
    int peer_id = -1;
    int recv_calls = 0;
    int halt_msgs = 0;
    int stop_calls = 0;
    TransportClientInstance::Send::Ptr send;

    /**
     * @brief Report whether the session is still live.
     * @return False once stopped or once it has died on its first packet.
     */
    bool defined() const override
    {
        return !dead_ && stop_calls == 0;
    }

    /** @brief Record the stop. */
    void stop() override
    {
        ++stop_calls;
    }

    /**
     * @brief Record the start and keep the sender for later sends.
     * @param parent The transport's per-client sender.
     * @param addr Unused.
     * @param local_peer_id The peer id the server assigned.
     * @param cookie_psid Unused.
     */
    void start(const TransportClientInstance::Send::Ptr &parent,
               [[maybe_unused]] const PeerAddr::Ptr &addr,
               const int local_peer_id,
               [[maybe_unused]] const ProtoSessionID cookie_psid) override
    {
        started = true;
        send = parent;
        peer_id = local_peer_id;
    }

    /**
     * @brief Accept a packet, or end the session if scripted to.
     * @param buf Unused.
     * @return True.
     */
    bool transport_recv([[maybe_unused]] BufferAllocated &buf) override
    {
        if (++recv_calls == 1 && die_on_first_recv)
        {
            dead_ = true;
        }
        return true;
    }

    /**
     * @brief Send @c halt_msg_packets packets to the client, as a RESTART push would.
     * @param type Unused.
     * @param reason Unused.
     * @param client_reason Unused.
     */
    void push_halt_restart_msg([[maybe_unused]] const HaltRestart::Type type,
                               [[maybe_unused]] const std::string &reason, // NOLINT(bugprone-easily-swappable-parameters) -- signature fixed by Recv
                               [[maybe_unused]] const std::string &client_reason) override
    {
        ++halt_msgs;
        // Headroom for the TCP link's length prefix, as a framed buffer has.
        constexpr std::size_t capacity = 64;
        constexpr std::size_t headroom = 16;
        BufferAllocated buf(capacity, BufAllocFlags::NO_FLAGS);
        buf.init_headroom(headroom);
        buf.write(client_reset_packet.data(), client_reset_packet.size());
        for (int sent = 0; sent < halt_msg_packets && send; ++sent)
        {
            send->transport_send_const(buf);
        }
    }

    /**
     * @brief Unused.
     * @return True.
     */
    bool is_keepalive_enabled() const override
    {
        return true;
    }

    /**
     * @brief Unused.
     * @param keepalive_ping Unused.
     * @param keepalive_timeout Unused.
     */
    void disable_keepalive([[maybe_unused]] unsigned int &keepalive_ping, // NOLINT(bugprone-easily-swappable-parameters) -- signature fixed by Recv
                           [[maybe_unused]] unsigned int &keepalive_timeout) override
    {
    }

    /**
     * @brief Unused.
     * @param dc_factory Unused.
     */
    void override_dc_factory([[maybe_unused]] const CryptoDCFactory::Ptr &dc_factory) override
    {
    }

    /**
     * @brief Unused.
     * @param tun Unused.
     * @return Null.
     */
    TunClientInstance::Recv *override_tun([[maybe_unused]] TunClientInstance::Send *tun) override
    {
        return nullptr;
    }

    /**
     * @brief Unused.
     * @param stats Unused.
     * @param final Unused.
     */
    void stats_notify([[maybe_unused]] const PeerStats &stats, [[maybe_unused]] const bool final) override
    {
    }

    /**
     * @brief Unused.
     * @param addr Unused.
     */
    void float_notify([[maybe_unused]] const PeerAddr::Ptr &addr) override
    {
    }

    /**
     * @brief Unused.
     * @param ipma Unused.
     */
    void ipma_notify([[maybe_unused]] const struct ovpn_tun_head_ipma &ipma) override
    {
    }

    /**
     * @brief Unused.
     * @param key_id Unused.
     * @param cdl_mode Unused.
     * @param cdl_status Unused.
     */
    void data_limit_notify([[maybe_unused]] const int key_id,
                           [[maybe_unused]] const DataLimit::Mode cdl_mode,
                           [[maybe_unused]] const DataLimit::State cdl_status) override
    {
    }

  private:
    bool dead_ = false;
};

/**
 * @brief @c ServerProto::Factory with no tls-auth or tls-crypt, handing out
 *  @c FakeSession objects.
 * @details With neither wrapper configured, prevalidation accepts everything
 *  and the UDP psid cookie declines, so a bare hard-reset opcode is enough to
 *  open a session.
 */
class FakeFactory : public ServerProto::Factory
{
  public:
    using Ptr = RCPtr<FakeFactory>;

    /**
     * @brief Construct the factory over a default protocol configuration.
     * @param io_context Event loop handed to the base factory.
     * @param proto_config Default protocol configuration; kept for the cookie component.
     */
    FakeFactory(openvpn_io::io_context &io_context, const ProtoConfig::Ptr &proto_config)
        : ServerProto::Factory(io_context, *proto_config)
    {
        proto_context_config = proto_config;
        stats.reset(new SessionStats());
    }

    /**
     * @brief Create the next session, applying the per-session script.
     * @return A new @c FakeSession, also recorded in @c sessions.
     */
    TransportClientInstance::Recv::Ptr new_client_instance() override
    {
        const FakeSession::Ptr session(new FakeSession());
        const std::size_t index = sessions.size();
        if (index < die_on_first_recv.size())
        {
            session->die_on_first_recv = die_on_first_recv.at(index);
        }
        if (index < halt_msg_packets.size())
        {
            session->halt_msg_packets = halt_msg_packets.at(index);
        }
        sessions.push_back(session);
        return session;
    }

    /** @brief Per creation order: whether that session dies on its first packet. */
    std::vector<bool> die_on_first_recv;

    /** @brief Per creation order: packets that session sends on a halt push. */
    std::vector<int> halt_msg_packets;

    std::vector<FakeSession::Ptr> sessions;
};

/** @brief Payload size for the frames the tests' servers are configured with. */
inline constexpr std::size_t test_frame_payload = 2048;

/**
 * @brief Run @p io_context until @p done holds or about two seconds pass.
 * @tparam Pred Nullary callable returning bool.
 * @param io_context The event loop to run.
 * @param done Completion predicate.
 * @return The final value of @p done.
 */
template <typename Pred>
bool pump_until(openvpn_io::io_context &io_context, Pred done)
{
    constexpr int max_rounds = 200;
    constexpr std::chrono::milliseconds round_time{10};
    for (int round = 0; round < max_rounds && !done(); ++round)
    {
        io_context.restart();
        io_context.run_for(round_time);
    }
    return done();
}

/**
 * @brief Extract the port from a server's @c local_endpoint_info().
 * @param info A string of the form @c "<addr>:<port>".
 * @return The port.
 */
inline std::uint16_t port_of(const std::string &info)
{
    return static_cast<std::uint16_t>(std::stoul(info.substr(info.rfind(':') + 1)));
}

} // namespace openvpn::test

#endif
