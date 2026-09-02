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
 * @brief Address allocation and dest-address routing for the classic (non-DCO)
 *  server data path, as two separate types.
 *
 * @details
 * Two questions, answered by two objects held by two different layers:
 *
 * - @c AddressPool: which addresses are free? Owned by the management layer,
 *   which is the only thing that allocates. Deliberately not @c IP::Pool
 *   (`openvpn/addr/pool.hpp`): that type keys an @c unordered_map on the
 *   address, so it only compiles where @c std::hash is specialized for it,
 *   which core does only under @c HAVE_XXHASH. Depending on it would make an
 *   optional build dependency mandatory for every consumer of this header.
 *   A free list over @c IP::Range costs less than that.
 * - @c RouteTable: which session owns a destination address? The only thing
 *   the tun layer holds, and it can do nothing but look up, because looking up
 *   is all the tun layer does.
 *
 * @c Lease binds the two. Acquiring one takes an address from the pool and
 * registers it in the route table; destroying one undoes both. That pairing is
 * the whole reason the type exists: an earlier revision assigned in the
 * management factory and released in the tun instance's @c stop(), and a
 * session denied or aborted before a tun instance was lazily created never
 * released at all. Moving both halves into the management layer fixed it by
 * convention; a move-only lease fixes it by construction, so no teardown path
 * has to remember.
 *
 * Both layers reach a session through a common identity:
 * `ServerProto::Session` multiply-inherits `TransportClientInstance::Recv`,
 * `TunClientInstance::Recv`, and `ManClientInstance::Recv` (see
 * `openvpn/common/link.hpp`), so a `ManClientInstance::Recv*` and a
 * `TunClientInstance::Recv*` obtained from the same session are the same
 * object and `dynamic_cast` between the sibling interfaces resolves correctly.
 * Only @c Lease's constructor needs that cast now; teardown is keyed by
 * address, which the lease already holds.
 *
 * @note Storing a raw session pointer is interim. Keying on a session id, with
 *  a registry resolving id to session, is what removes the pointer from the
 *  routing structure entirely, and it needs the session manager
 *  `rfc-o3-server-engine.md` specifies. The same document replaces this
 *  exact-match table with longest-prefix-match routing, which is what per-client
 *  subnets need and what this cannot express.
 */

#ifndef OPENVPN_SERVER_PEERROUTES_H
#define OPENVPN_SERVER_PEERROUTES_H

#include <deque>
#include <map>
#include <optional>
#include <utility>

#include <openvpn/common/exception.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/range.hpp>
#include <openvpn/tun/server/tunbase.hpp>

namespace openvpn::PeerRoutes {

OPENVPN_EXCEPTION(peer_routes_error);

/**
 * @brief The address range clients are assigned from.
 */
struct Config
{
    /** First address handed out; subsequent clients get successors. */
    IP::Addr pool_start = IP::Addr::from_string("10.8.0.2");

    /** Number of addresses available from @c pool_start onward. */
    unsigned int pool_size = 252;
};

/**
 * @brief Resolves a packet's destination address to the session that owns it.
 *
 * @details
 * Written by the management layer through @c Lease, read by the tun layer's
 * device read loop. Deliberately exposes no way to allocate: the tun layer
 * holds one of these and calls nothing but @c lookup().
 *
 * Not thread-safe; assumed to be called only from the single control-plane
 * `io_context` thread, matching every other component in this server.
 */
class RouteTable
{
  public:
    /**
     * @brief Find the session that owns a destination address.
     * @param addr The address to look up.
     * @return The owning session, or @c nullptr if unassigned.
     */
    TunClientInstance::Recv *lookup(const IP::Addr &addr) const
    {
        const auto it = by_addr_.find(addr);
        return it != by_addr_.end() ? it->second : nullptr;
    }

    /**
     * @brief The address routed to a session, if any.
     * @details The reverse of @c lookup(). Exists for the tun layer's ingress
     *  reverse-path check, which needs to know what a session is allowed to
     *  source from (tunreal.hpp's @c source_is_permitted). Linear in the table
     *  because it runs once per session, at tun-object creation, not per
     *  packet.
     * @param session The session to look up.
     * @return Its routed address, or @c std::nullopt if it has none.
     */
    std::optional<IP::Addr> addr_for(const TunClientInstance::Recv *session) const
    {
        for (const auto &kv : by_addr_)
            if (kv.second == session)
                return kv.first;
        return std::nullopt;
    }

    /**
     * @brief Number of addresses currently routed.
     * @return The live route count.
     */
    size_t size() const
    {
        return by_addr_.size();
    }

  private:
    friend class Lease;

    /**
     * @brief Route an address to a session. Called only by @c Lease.
     * @param addr The address to route.
     * @param session The session that owns it.
     */
    void add(const IP::Addr &addr, TunClientInstance::Recv *session)
    {
        // Assigning would silently re-point an address at a second session and
        // strand the first one's traffic; a duplicate is a caller bug.
        if (!by_addr_.emplace(addr, session).second)
            throw Exception("PeerRoutes::RouteTable: address already routed: " + addr.to_string());
    }

    /**
     * @brief Stop routing an address. Called only by @c Lease.
     * @param addr The address to drop.
     */
    void remove(const IP::Addr &addr)
    {
        by_addr_.erase(addr);
    }

    std::map<IP::Addr, TunClientInstance::Recv *> by_addr_;
};

/**
 * @brief The pool of client addresses.
 *
 * @details
 * Owned by the management layer, which is the only layer that allocates.
 * A free list over the configured @c IP::Range, with @c acquire() and
 * @c release() private so an address can only be taken and returned by a
 * @c Lease.
 *
 * Not thread-safe, same single-threaded assumption as @c RouteTable.
 */
class AddressPool
{
  public:
    /**
     * @brief Build the pool over the configured range.
     * @details Addresses are handed out from the front and returned to the
     *  back, so a released address is the last to be reused rather than the
     *  first. That delays reuse for as long as the pool allows, which matters
     *  because a reconnecting client can otherwise land on an address a peer
     *  still holds a stale neighbour entry for.
     * @param config The pool's starting address and size.
     */
    explicit AddressPool(const Config &config)
    {
        // An unspecified start yields pool_size copies of the same address, so
        // every lease would hold it. The server validates this too, but the
        // class must not depend on its caller to stay coherent.
        if (config.pool_start.unspecified())
            throw Exception("PeerRoutes::AddressPool: pool_start must be a specified address");
        for (const IP::Addr &addr : IP::Range(config.pool_start, config.pool_size))
            free_.push_back(addr);
    }

    /**
     * @brief Number of addresses still free.
     * @return The count of unallocated addresses.
     */
    size_t available() const
    {
        return free_.size();
    }

  private:
    friend class Lease;

    /**
     * @brief Take the next free address. Called only by @c Lease.
     * @return The acquired address.
     * @throws peer_routes_error if the pool is exhausted.
     */
    IP::Addr acquire()
    {
        if (free_.empty())
            throw peer_routes_error("address pool exhausted");
        const IP::Addr addr = free_.front();
        free_.pop_front();
        return addr;
    }

    /**
     * @brief Return an address to the pool. Called only by @c Lease.
     * @details Not guarded against a double release, because @c Lease is the
     *  only caller and releases exactly once.
     * @param addr The address to free.
     */
    void release(const IP::Addr &addr)
    {
        free_.push_back(addr);
    }

    std::deque<IP::Addr> free_;
};

/**
 * @brief One session's claim on an address: allocated from the pool and routed
 *  in the route table for exactly as long as this object lives.
 *
 * @details
 * Move-only, mirroring a file descriptor handle: exactly one owner releases.
 * Holding one is the whole of a session's address bookkeeping, so a teardown
 * path cannot release one half and forget the other, and a session that ends
 * before it ever had a tun instance still gives its address back.
 *
 * The pool and route table are borrowed and must outlive every lease taken
 * against them. `OpenVPNServer` owns both and outlives every session.
 */
class Lease
{
  public:
    /** @brief An empty lease, owning nothing. */
    Lease() = default;

    /**
     * @brief Take an address for a session and route it.
     * @param pool Pool to allocate from. Borrowed; must outlive this lease.
     * @param routes Route table to register in. Borrowed; same requirement.
     * @param session Session that will own the address, as the tun layer will
     *  look it up. Borrowed; the lease must not outlive it.
     * @throws peer_routes_error if the pool is exhausted.
     */
    Lease(AddressPool &pool, RouteTable &routes, TunClientInstance::Recv *session)
        : pool_(&pool),
          routes_(&routes),
          addr_(pool.acquire())
    {
        routes_->add(addr_, session);
    }

    Lease(const Lease &) = delete;
    Lease &operator=(const Lease &) = delete;

    Lease(Lease &&other) noexcept
        : pool_(std::exchange(other.pool_, nullptr)),
          routes_(std::exchange(other.routes_, nullptr)),
          addr_(other.addr_)
    {
    }

    Lease &operator=(Lease &&other) noexcept
    {
        if (this != &other)
        {
            release();
            pool_ = std::exchange(other.pool_, nullptr);
            routes_ = std::exchange(other.routes_, nullptr);
            addr_ = other.addr_;
        }
        return *this;
    }

    ~Lease()
    {
        release();
    }

    /**
     * @brief Drop the route and return the address to the pool.
     * @details Idempotent, so a teardown path that runs more than once stays
     *  safe. Called by the destructor; callable early by a caller that wants
     *  the address back before its own object dies.
     */
    void release()
    {
        if (!pool_)
            return;
        routes_->remove(addr_);
        pool_->release(addr_);
        pool_ = nullptr;
        routes_ = nullptr;
    }

    /**
     * @brief The leased address.
     * @details Stays readable after @c release(), so a teardown path can still
     *  name the address in a disconnect notification or a log line after
     *  giving it back. Undefined only on a lease that never held one.
     * @return The address.
     */
    const IP::Addr &addr() const
    {
        return addr_;
    }

    /** @brief Whether this lease currently holds an address. */
    explicit operator bool() const
    {
        return pool_ != nullptr;
    }

  private:
    AddressPool *pool_ = nullptr;
    RouteTable *routes_ = nullptr;
    IP::Addr addr_;
};

} // namespace openvpn::PeerRoutes

#endif
