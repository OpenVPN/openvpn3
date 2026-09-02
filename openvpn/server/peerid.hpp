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
 * @brief Peer-id allocation for the server transports.
 *
 * @details
 * A peer id is the 24-bit routing label a server puts in the DATA_V2 header and
 * pushes to the client as `peer-id`. It is also what the kernel DCO module keys
 * its per-peer state on, since `DcoServ` installs peers under the same value.
 *
 * This deliberately copies OpenVPN 2's shape (`multi_assign_peer_id()`,
 * `multi.c`), because that design makes two properties structural rather than
 * remembered:
 *
 *   - **The id cannot leave the wire field.** It is an index into a table sized
 *     by `max_clients`, and `max_clients` is checked against @c UNDEF once at
 *     construction. There is no per-allocation bound check to forget, and no
 *     way for a long-lived server to hand out an id that does not fit.
 *   - **Releasing the session releases the id.** Freeing the slot *is* the
 *     deallocation, so the two cannot drift apart. A monotonic counter with a
 *     separate reverse-index map -- which is what this replaces -- freed the
 *     map entry but never the id.
 *
 * The slot table doubles as the reverse index, so a peer-id lookup is an array
 * access rather than a second container kept in step by hand.
 *
 * **Reuse is immediate**, taking the lowest free slot, exactly as v2 does. That
 * is safe for the same reason it is safe there: teardown is atomic with respect
 * to allocation, because the server is single-threaded on one `io_context`. In
 * v2 the slot is actually cleared *before* the kernel peer is deleted
 * (`multi.c:603` then `close_context()` at `:640`), which only works because
 * nothing can allocate in between.
 *
 * Note the contrast with @c PeerRoutes::AddressPool, which deliberately delays
 * reuse. That matters for a tunnel address because a reconnecting client can
 * otherwise land on an address a *peer* was just using, and peers cache it. A
 * peer id is server-internal: nothing outside the server and its own kernel
 * module observes it, and the kernel's copy goes away in the same teardown. The
 * hazard that justifies delaying address reuse has no analogue here, which is
 * why v2 does not bother either.
 */

#ifndef OPENVPN_SERVER_PEERID_H
#define OPENVPN_SERVER_PEERID_H

#include <cstddef>
#include <algorithm>
#include <optional>
#include <vector>

#include <openvpn/common/exception.hpp>

namespace openvpn::PeerId {

/**
 * @brief The reserved "no peer id" value, and so the exclusive upper bound on
 *  a usable id.
 * @details Matches OpenVPN 2's @c MAX_PEER_ID (`openvpn.h`) and the mask
 *  `udptransserv.hpp`'s `extract_peer_id_hint()` applies to the DATA_V2 header.
 *  Usable ids are therefore `0 .. UNDEF - 1`.
 */
constexpr int UNDEF = 0x00FFFFFF;

/**
 * @brief Slot table allocating peer ids and mapping them back to a caller value.
 *
 * @tparam Value What the caller wants to recover from an id -- the client's
 *  endpoint for the UDP server, which needs it for peer float. A transport with
 *  no reverse lookup can instantiate it and simply not call @c find().
 */
template <typename Value>
class Table
{
  public:
    /**
     * @brief Build a table with room for @p max_clients concurrent peers.
     * @param max_clients Peer ids run from 0 to @p max_clients - 1.
     * @throws openvpn::Exception if @p max_clients would allow an id that does
     *  not fit the 24-bit wire field.
     */
    explicit Table(const std::size_t max_clients)
        : slots_(max_clients)
    {
        // v2 asserts the same relation once, for the same reason: it is what
        // makes every id it later hands out representable.
        if (max_clients >= static_cast<std::size_t>(UNDEF))
            throw Exception("PeerId::Table: max_clients must be below the 24-bit peer-id space");
    }

    /**
     * @brief Claim the lowest free id.
     * @param value What @c find() should return for it.
     * @return The id, or no value when every slot is occupied.
     */
    std::optional<int> acquire(const Value &value)
    {
        for (std::size_t i = 0; i < slots_.size(); ++i)
        {
            if (!slots_[i].has_value())
            {
                slots_[i] = value;
                ++in_use_;
                return static_cast<int>(i);
            }
        }
        return std::nullopt;
    }

    /**
     * @brief Return an id to the table.
     * @details Idempotent, and ignores an id that was never issued, so a
     *  teardown path that runs twice or on a session that never got an id needs
     *  no guard of its own.
     * @param peer_id The id to free.
     */
    void release(const int peer_id)
    {
        if (!in_range(peer_id) || !slots_[static_cast<std::size_t>(peer_id)].has_value())
            return;
        slots_[static_cast<std::size_t>(peer_id)].reset();
        --in_use_;
    }

    /**
     * @brief Look up what an id was issued for.
     * @param peer_id The id to resolve.
     * @return Pointer to the value, or @c nullptr if the id is out of range or
     *  not currently issued.
     */
    const Value *find(const int peer_id) const
    {
        if (!in_range(peer_id) || !slots_[static_cast<std::size_t>(peer_id)].has_value())
            return nullptr;
        return &*slots_[static_cast<std::size_t>(peer_id)];
    }

    /**
     * @brief Re-point an already-issued id at a new value.
     * @details For peer float: the session keeps its id and moves endpoint.
     *  Does nothing for an id that is not currently issued.
     * @param peer_id The id to update.
     * @param value The new value.
     */
    void update(const int peer_id, const Value &value)
    {
        if (in_range(peer_id) && slots_[static_cast<std::size_t>(peer_id)].has_value())
            slots_[static_cast<std::size_t>(peer_id)] = value;
    }

    /** @brief Release every id. */
    void clear()
    {
        std::ranges::fill(slots_, std::nullopt);
        in_use_ = 0;
    }

    /** @brief How many ids are currently issued. */
    std::size_t in_use() const
    {
        return in_use_;
    }

    /** @brief How many ids the table can issue at once. */
    std::size_t max_supported_slots() const
    {
        return slots_.size();
    }

  private:
    bool in_range(const int peer_id) const
    {
        return peer_id >= 0 && static_cast<std::size_t>(peer_id) < slots_.size();
    }

    std::vector<std::optional<Value>> slots_;
    std::size_t in_use_ = 0;
};

} // namespace openvpn::PeerId

#endif
