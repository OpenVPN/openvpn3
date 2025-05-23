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

// Manage OpenVPN protocol Packet IDs for packet replay detection

#pragma once

#include <string>
#include <cstring>
#include <sstream>
#include <cstdint> // for std::uint32_t

#include <openvpn/io/io.hpp>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/circ_list.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/common/likely.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/log/sessionstats.hpp>

namespace openvpn {
/*
 * Control channel Packet ID. These IDs have the format
 *
 *  | 32 bit integer timestamp in BE | 32 bit packet counter in BE |
 *
 * This format of long packet-ids is also used as IVs for CFB/OFB ciphers
 * in OpenVPN 2.x but OpenVPN 3.x supports only CBC and AEAD ciphers, so
 * it is only used for control channel and control chanel authentication/encryption
 * schemes like tls-auth/tls-crypt.
 *
 * This data structure is always sent over the net in network byte order,
 * by calling htonl, ntohl, on the 32-bit data elements, id_t and
 * net_time_t, to change them to and from network order.
 */
struct PacketIDControl
{
    typedef std::uint32_t id_t;
    typedef std::uint32_t net_time_t;
    typedef Time::base_type time_t;

    id_t id;     // legal values are 1 through 2^32-1
    time_t time; // converted to PacketID::net_time_t before transmission

    static constexpr size_t size()
    {
        return idsize;
    }

    constexpr static size_t idsize = sizeof(id_t) + sizeof(net_time_t);

    bool is_valid() const
    {
        return id != 0;
    }

    void reset()
    {
        id = id_t(0);
        time = time_t(0);
    }

    template <typename BufType> // so it can take a Buffer or a ConstBuffer
    void read(BufType &buf)
    {
        id_t net_id;
        net_time_t net_time;

        buf.read((unsigned char *)&net_id, sizeof(net_id));
        id = ntohl(net_id);

        buf.read((unsigned char *)&net_time, sizeof(net_time));
        time = ntohl(net_time);
    }

    void write(Buffer &buf, const bool prepend) const
    {
        const id_t net_id = htonl(id);
        const net_time_t net_time = htonl(static_cast<uint32_t>(time & 0x00000000FFFFFFFF));
        // TODO: [OVPN3-931] Make our code handle rollover of this value gracefully as possible
        // since at the current time this will probably force a reconnect.

        if (prepend)
        {
            buf.prepend((unsigned char *)&net_time, sizeof(net_time));
            buf.prepend((unsigned char *)&net_id, sizeof(net_id));
        }
        else
        {
            buf.write((unsigned char *)&net_id, sizeof(net_id));
            buf.write((unsigned char *)&net_time, sizeof(net_time));
        }
    }

    std::string str() const
    {
        std::ostringstream os;
        os << std::hex << "[0x" << time << ", 0x" << id << "]";
        return os.str();
    }
};


class PacketIDControlSend
{
  public:
    OPENVPN_SIMPLE_EXCEPTION(packet_id_wrap);


    explicit PacketIDControlSend(PacketIDControl::id_t start_at = PacketIDControl::id_t(0))
    {
        init(start_at);
    }

    /**
     * @param start_at initial id for the sending
     */
    void init(PacketIDControl::id_t start_at = 0)
    {
        pid_.id = start_at;
        pid_.time = PacketIDControl::time_t(0);
    }

    PacketIDControl next(const PacketIDControl::time_t now)
    {
        PacketIDControl ret;
        if (!pid_.time)
            pid_.time = now;
        ret.id = ++pid_.id;
        if (unlikely(!pid_.id)) // wraparound
        {
            pid_.time = now;
            ret.id = pid_.id = 1;
        }
        ret.time = pid_.time;
        return ret;
    }

    void write_next(Buffer &buf, const bool prepend, const PacketIDControl::time_t now)
    {
        const PacketIDControl pid = next(now);
        pid.write(buf, prepend);
    }

    std::string str() const
    {
        return pid_.str() + 'L';
    }

  private:
    PacketIDControl pid_;
};

/*
 * This is the data structure we keep on the receiving side,
 * to check that no packet-id (i.e. sequence number + optional timestamp)
 * is accepted more than once.
 *
 * Replay window sizing in bytes = 2^REPLAY_WINDOW_ORDER.
 * PKTID_RECV_EXPIRE is backtrack expire in seconds.
 */
template <unsigned int REPLAY_WINDOW_ORDER,
          unsigned int PKTID_RECV_EXPIRE>
class PacketIDControlReceiveType
{
  public:
    static constexpr unsigned int REPLAY_WINDOW_BYTES = 1 << REPLAY_WINDOW_ORDER;
    static constexpr unsigned int REPLAY_WINDOW_SIZE = REPLAY_WINDOW_BYTES * 8;

    OPENVPN_SIMPLE_EXCEPTION(packet_id_not_initialized);

    // TODO: [OVPN3-933] Consider RAII'ifying this code
    PacketIDControlReceiveType() = default;

    void init(const char *name_arg,
              const int unit_arg,
              const SessionStats::Ptr &stats_arg)
    {
        initialized_ = true;
        base = 0;
        extent = 0;
        expire = 0;
        id_high = 0;
        time_high = 0;
        id_floor = 0;
        max_backtrack = 0;
        unit = unit_arg;
        name = name_arg;
        stats = stats_arg;
        std::memset(history, 0, sizeof(history));
    }

    [[nodiscard]] bool initialized() const
    {
        return initialized_;
    }

    bool test_add(const PacketIDControl &pin,
                  const PacketIDControl::time_t now,
                  const bool mod) // don't modify history unless mod is true
    {
        const Error::Type err = do_test_add(pin, now, mod);
        if (unlikely(err != Error::SUCCESS))
        {
            stats->error(err);
            return false;
        }
        else
            return true;
    }

    Error::Type do_test_add(const PacketIDControl &pin,
                            const PacketIDControl::time_t now,
                            const bool mod) // don't modify history unless mod is true
    {
        // make sure we were initialized
        if (unlikely(!initialized_))
            throw packet_id_not_initialized();

        // expire backtracks at or below id_floor after PKTID_RECV_EXPIRE time
        if (unlikely(now >= expire))
            id_floor = id_high;
        expire = now + PKTID_RECV_EXPIRE;

        // ID must not be zero
        if (unlikely(!pin.is_valid()))
            return Error::PKTID_INVALID;

        // time changed?
        if (unlikely(pin.time != time_high))
        {
            if (pin.time > time_high)
            {
                // time moved forward, accept
                if (!mod)
                    return Error::SUCCESS;
                base = 0;
                extent = 0;
                id_high = 0;
                time_high = pin.time;
                id_floor = 0;
            }
            else
            {
                // time moved backward, reject
                return Error::PKTID_TIME_BACKTRACK;
            }
        }

        if (likely(pin.id == id_high + 1))
        {
            // well-formed ID sequence (incremented by 1)
            if (!mod)
                return Error::SUCCESS;
            base = REPLAY_INDEX(-1);
            history[base / 8] |= static_cast<uint8_t>(1 << (base % 8));
            if (extent < REPLAY_WINDOW_SIZE)
                ++extent;
            id_high = pin.id;
        }
        else if (pin.id > id_high)
        {
            // ID jumped forward by more than one
            if (!mod)
                return Error::SUCCESS;
            const unsigned int delta = pin.id - id_high;
            if (delta < REPLAY_WINDOW_SIZE)
            {
                base = REPLAY_INDEX(-delta);
                history[base / 8] |= static_cast<uint8_t>(1 << (base % 8));
                extent += delta;
                if (extent > REPLAY_WINDOW_SIZE)
                    extent = REPLAY_WINDOW_SIZE;
                for (unsigned i = 1; i < delta; ++i)
                {
                    const unsigned int newbase = REPLAY_INDEX(i);
                    history[newbase / 8] &= static_cast<uint8_t>(~(1 << (newbase % 8)));
                }
            }
            else
            {
                base = 0;
                extent = REPLAY_WINDOW_SIZE;
                std::memset(history, 0, sizeof(history));
                history[0] = 1;
            }
            id_high = pin.id;
        }
        else
        {
            // ID backtrack
            const unsigned int delta = id_high - pin.id;
            if (delta > max_backtrack)
                max_backtrack = delta;
            if (delta < extent)
            {
                if (pin.id > id_floor)
                {
                    const unsigned int ri = REPLAY_INDEX(delta);
                    std::uint8_t *p = &history[ri / 8];
                    const std::uint8_t mask = static_cast<uint8_t>(1 << (ri % 8));
                    if (*p & mask)
                        return Error::PKTID_REPLAY;
                    if (!mod)
                        return Error::SUCCESS;
                    *p |= mask;
                }
                else
                    return Error::PKTID_EXPIRE;
            }
            else
                return Error::PKTID_BACKTRACK;
        }

        return Error::SUCCESS;
    }

    PacketIDControl read_next(Buffer &buf) const
    {
        if (!initialized_)
            throw packet_id_not_initialized();
        PacketIDControl pid{};
        pid.read(buf);
        return pid;
    }

    std::string str() const
    {
        std::ostringstream os;
        os << "[e=" << extent << " f=" << id_floor << " h=" << time_high << '/' << id_high << ']';
        return os.str();
    }

  private:
    unsigned int REPLAY_INDEX(const int i) const
    {
        return (base + i) & (REPLAY_WINDOW_SIZE - 1);
    }

    bool initialized_ = false;

    unsigned int base = 0;                 // bit position of deque base in history
    unsigned int extent = 0;               // extent (in bits) of deque in history
    PacketIDControl::time_t expire = 0;    // expiration of history
    PacketIDControl::id_t id_high = 0;     // highest sequence number received
    PacketIDControl::time_t time_high = 0; // highest time stamp received
    PacketIDControl::id_t id_floor = 0;    // we will only accept backtrack IDs > id_floor
    unsigned int max_backtrack = 0;

    int unit = -1;    // unit number of this object (for debugging)
    std::string name; // name of this object (for debugging)

    SessionStats::Ptr stats;

    std::uint8_t history[REPLAY_WINDOW_BYTES]; /* "sliding window" bitmask of recent packet IDs received */
};

// Our standard packet ID window with order=8 (window size=2048).
// and recv expire=30 seconds.
typedef PacketIDControlReceiveType<8, 30> PacketIDControlReceive;

} // namespace openvpn
