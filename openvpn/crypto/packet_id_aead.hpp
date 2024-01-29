//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Manage OpenVPN protocol Packet IDs for packet replay detection
#pragma once

#include <algorithm>
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
#include <openvpn/common/endian64.hpp>
#include <openvpn/error/error.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/log/sessionstats.hpp>

namespace openvpn {
/**
 * Communicate packet-id over the wire for AEAD
 * A short packet-id is just a 32 bit sequence number. A long packet-id is a
 * 64 bit sequence number. This sequence number is reused for AEAD IV.
 *
 * This data structure is always sent over the net in network byte order,
 *
 * This class is different from PacketID in the way that it always uses
 * a "flat" packet id that is either 32 or 64 bit while PacketID has a long
 * packet id that is 32bit + 32bit but follow different rules and includes
 * a timestamp. Merging PacketIDAEAD and PacketID would result in a much
 * more convoluted and hard to understand class than keeping them seperate
 *
 */
struct PacketIDAEAD
{
    typedef std::uint64_t aead_id_t;

    aead_id_t id = 0; // legal values are 1 through 2^64-1
    bool wide = false;

    /**
     * Returns the size of the packet id. This is either 4 or 8 depending on the mode in use
     * @return 4 or 8
     */
    [[nodiscard]] constexpr std::size_t size() const
    {
        return size(wide);
    }

    static constexpr size_t size(bool wide)
    {
        if (wide)
            return long_id_size;
        else
            return short_id_size;
    }


    explicit PacketIDAEAD(bool wide_arg)
        : wide(wide_arg)
    {
    }

    explicit PacketIDAEAD(bool wide_arg, aead_id_t id_arg)
        : id(id_arg), wide(wide_arg)
    {
    }

    constexpr static std::size_t short_id_size = sizeof(std::uint32_t);
    constexpr static std::size_t long_id_size = sizeof(std::uint64_t);

    bool is_valid() const
    {
        return id != 0;
    }

    void reset()
    {
        id = aead_id_t(0);
    }

    /**
     * Reads the packet id from the specified buffer.
     * @param buf       the buffer to read the packet id from
     */
    void read(ConstBuffer &buf)
    {
        if (wide)
        {
            std::uint64_t net_id;
            buf.read(reinterpret_cast<unsigned char *>(&net_id), sizeof(net_id));
            id = Endian::rev64(net_id);
        }
        else
        {
            std::uint32_t net_id;
            buf.read(reinterpret_cast<unsigned char *>(&net_id), sizeof(net_id));
            id = ntohl(net_id);
        }
    }

    /** Writes the packet id to a buffer */
    void write(Buffer &buf) const
    {
        if (wide)
        {
            const std::uint64_t net_id = Endian::rev64(id);
            buf.write(reinterpret_cast<const unsigned char *>(&net_id), sizeof(net_id));
        }
        else
        {
            const std::uint32_t net_id = htonl(static_cast<std::uint32_t>(id));
            buf.write(reinterpret_cast<const unsigned char *>(&net_id), sizeof(net_id));
        }
    }

    std::string str() const
    {
        std::ostringstream os;
        os << std::hex << "[0x" << id << "]";
        return os.str();
    }
};

class PacketIDAEADSend
{
  public:
    OPENVPN_SIMPLE_EXCEPTION(packet_id_wrap);

    PacketIDAEADSend(bool wide_arg)
        : pid_(wide_arg)
    {
    }


    /**
     * Increment the packet ID and return the next packet id to use.
     * @throws  packet_id_wrap if the packet id space is exhausted
     * @return  packet id to use next.
     */
    PacketIDAEAD next()
    {
        ++pid_.id;
        PacketIDAEAD ret{pid_.wide, pid_.id};
        if (!pid_.wide && unlikely(pid_.id == std::numeric_limits<std::uint32_t>::max())) // wraparound
        {
            throw packet_id_wrap();
        }
        else if (unlikely(pid_.id == std::numeric_limits<decltype(pid_.id)>::max()))
        {
            throw packet_id_wrap();
        }
        return ret;
    }

    /**
     * increases the packet id and writes it to a buffer
     * @param buf   buffer to write to
     */
    void write_next(Buffer &buf)
    {
        const PacketIDAEAD pid = next();
        pid.write(buf);
    }

    /**
     * When a VPN runs in TLS mode (the only mode that OpenVPN supports,
     * there is no --secret mode anymore), it needs to be warned about wrapping to
     * start thinking about triggering a new SSL/TLS handshake.
     * This method can be called to see if that level has been reached.
     */
    bool wrap_warning() const
    {
        if (pid_.wide)
            return false;

        const PacketIDAEAD::aead_id_t wrap_at = 0xFF000000;
        return pid_.id >= wrap_at;
    }

    std::string str() const
    {
        std::string ret;
        ret = pid_.str();
        if (pid_.wide)
            ret += 'L';
        return ret;
    }

    /**
     * Returns the size of the packet id. This is either 4 or 8 depending on the mode in use
     * @return 4 or 8
     */
    [[nodiscard]] constexpr std::size_t length() const
    {
        return pid_.size();
    }

  private:
    PacketIDAEAD pid_;
};

/*
 * This is the data structure we keep on the receiving side,
 * to check that no packet-id is accepted more than once.
 *
 * Replay window sizing in bytes = 2^REPLAY_WINDOW_ORDER.
 * PKTID_RECV_EXPIRE is backtrack expire in seconds.
 */
template <unsigned int REPLAY_WINDOW_ORDER,
          unsigned int PKTID_RECV_EXPIRE>
class PacketIDAEADReceiveType
{
  public:
    static constexpr unsigned int REPLAY_WINDOW_BYTES = 1u << REPLAY_WINDOW_ORDER;
    static constexpr unsigned int REPLAY_WINDOW_SIZE = REPLAY_WINDOW_BYTES * 8;

    void init(const char *name_arg,
              const int unit_arg,
              bool wide_arg,
              const SessionStats::Ptr &stats_arg)
    {
        wide = wide_arg;
        base = 0;
        extent = 0;
        expire = 0;
        id_high = 0;
        id_floor = 0;
        unit = unit_arg;
        name = name_arg;
        stats = stats_arg;
        std::memset(history, 0, sizeof(history));
    }


    /**
     * Checks if a packet ID is allowed and modifies the history of seen packets ids and
     * adds any errors to the internal stats.
     *
     * It returns the verdict of the packet id if it is fine or not
     *
     * @param pin       packet ID to check
     * @param now       Current time to check that reordered packets are in the allowed time
     * @return          true if the packet id is okay and has been accepted
     */
    [[nodiscard]] bool test_add(const PacketIDAEAD &pin,
                                const Time::base_type now)
    {
        const Error::Type err = do_test_add(pin, now);
        if (unlikely(err != Error::SUCCESS))
        {
            stats->error(err);
            return false;
        }
        else
            return true;
    }

    /**
     * Checks if a packet ID is allowed and modifies the history of seen packets ids.
     *
     * It returns the verdict of the packet id if it is fine or not
     *
     * @param pin       packet ID to check
     * @param now       Current time to check that reordered packets are in the allowed time
     * @return          Error::SUCCESS if successful, otherwise  PKTID_EXPIRE, PKTID_BACKTRACK or PKTID_REPLAY
     */
    [[nodiscard]] Error::Type do_test_add(const PacketIDAEAD &pin,
                                          const Time::base_type now)
    {
        // expire backtracks at or below id_floor after PKTID_RECV_EXPIRE time
        if (unlikely(now >= expire))
            id_floor = id_high;
        expire = now + PKTID_RECV_EXPIRE;

        // ID must not be zero
        if (unlikely(!pin.is_valid()))
            return Error::PKTID_INVALID;


        if (likely(pin.id == id_high + 1))
        {
            // well-formed ID sequence (incremented by 1)
            base = replay_index(-1);
            history[base / 8] |= static_cast<uint8_t>(1 << (base % 8));
            if (extent < REPLAY_WINDOW_SIZE)
                ++extent;
            id_high = pin.id;
        }
        else if (pin.id > id_high)
        {
            // ID jumped forward by more than one

            const auto delta = pin.id - id_high;
            if (delta < REPLAY_WINDOW_SIZE)
            {
                base = replay_index(-delta);
                history[base / 8] |= static_cast<uint8_t>(1u << (base % 8));
                extent += static_cast<std::size_t>(delta);
                if (extent > REPLAY_WINDOW_SIZE)
                    extent = REPLAY_WINDOW_SIZE;
                for (unsigned i = 1; i < delta; ++i)
                {
                    const auto newbase = replay_index(i);
                    history[newbase / 8] &= static_cast<uint8_t>(~(1u << (newbase % 8)));
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
            const auto delta = id_high - pin.id;
            if (delta < extent)
            {
                if (pin.id > id_floor)
                {
                    const auto ri = replay_index(delta);
                    std::uint8_t *p = &history[ri / 8];
                    const std::uint8_t mask = static_cast<uint8_t>(1u << (ri % 8));
                    if (*p & mask)
                        return Error::PKTID_REPLAY;
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

    PacketIDAEAD read_next(Buffer &buf) const
    {
        PacketIDAEAD pid{wide};
        pid.read(buf);
        return pid;
    }

    [[nodiscard]] std::string str() const
    {
        std::ostringstream os;
        os << "[e=" << extent << " f=" << id_floor << id_high << ']';
        return os.str();
    }

    [[nodiscard]] std::size_t constexpr length() const
    {
        return PacketIDAEAD::size(wide);
    }

  private:
    [[nodiscard]] constexpr std::size_t replay_index(PacketIDAEAD::aead_id_t i) const
    {
        return (base + i) & (REPLAY_WINDOW_SIZE - 1);
    }

    std::size_t base;                 // bit position of deque base in history
    std::size_t extent;               // extent (in bits) of deque in history
    Time::base_type expire;           // expiration of history
    PacketIDAEAD::aead_id_t id_high;  // highest sequence number received
    PacketIDAEAD::aead_id_t id_floor; // we will only accept backtrack IDs > id_floor

    //!< 32 or 64 bit packet counter
    bool wide;
    int unit;         // unit number of this object (for debugging)
    std::string name; // name of this object (for debugging)

    SessionStats::Ptr stats;

    //! "sliding window" bitmask of recent packet IDs received */
    std::uint8_t history[REPLAY_WINDOW_BYTES];
};

// Our standard packet ID window with order=8 (window size=2048).
// and recv expire=30 seconds.
typedef PacketIDAEADReceiveType<8, 30> PacketIDAEADReceive;

} // namespace openvpn
