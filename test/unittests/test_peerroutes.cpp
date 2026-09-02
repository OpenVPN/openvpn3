#include "test_common.hpp"
#include "test_generators.hpp"

#include <deque>
#include <set>
#include <utility>
#include <vector>

#include <openvpn/server/peerroutes.hpp>

using namespace openvpn;

namespace {

class FakeSession : public TunClientInstance::Recv
{
  public:
    void stop() override
    {
    }
    void tun_recv(BufferAllocated & /* buf */) override
    {
    }
    void push_halt_restart_msg(const HaltRestart::Type /* type */,
                               const std::string & /* reason */,
                               const std::string & /* client_reason */) override
    {
    }
};

PeerRoutes::Config make_config(const unsigned int pool_size = 252)
{
    PeerRoutes::Config c;
    c.pool_start = IP::Addr::from_string("10.8.0.2");
    c.pool_size = pool_size;
    return c;
}

} // namespace

TEST(PeerRoutesPool, HandsOutAddressesFromPoolStartUpward)
{
    PeerRoutes::AddressPool pool(make_config());
    PeerRoutes::RouteTable routes;
    FakeSession s1, s2, s3;

    PeerRoutes::Lease l1(pool, routes, &s1);
    PeerRoutes::Lease l2(pool, routes, &s2);
    PeerRoutes::Lease l3(pool, routes, &s3);

    ASSERT_EQ(l1.addr(), IP::Addr::from_string("10.8.0.2"));
    ASSERT_EQ(l2.addr(), IP::Addr::from_string("10.8.0.3"));
    ASSERT_EQ(l3.addr(), IP::Addr::from_string("10.8.0.4"));
    ASSERT_EQ(pool.available(), 252u - 3u);
    ASSERT_EQ(routes.size(), 3u);
}

TEST(PeerRoutesPool, ThrowsOncePoolIsExhausted)
{
    PeerRoutes::AddressPool pool(make_config(1));
    PeerRoutes::RouteTable routes;
    FakeSession s1, s2;

    PeerRoutes::Lease l1(pool, routes, &s1);
    ASSERT_THROW(PeerRoutes::Lease(pool, routes, &s2), PeerRoutes::peer_routes_error);

    // The failed acquire must not have consumed anything or left a route
    // behind for a session that never got an address.
    ASSERT_EQ(pool.available(), 0u);
    ASSERT_EQ(routes.size(), 1u);
}

TEST(PeerRoutesPool, ReleasedAddressIsReusedLastNotFirst)
{
    // FIFO reuse: the address freed first is the last one handed back out,
    // so a reconnecting client does not immediately inherit the address a
    // peer may still have a stale neighbour entry for.
    PeerRoutes::AddressPool pool(make_config(3));
    PeerRoutes::RouteTable routes;
    FakeSession s1, s2, s3, s4;

    PeerRoutes::Lease l1(pool, routes, &s1);
    const IP::Addr first = l1.addr();
    PeerRoutes::Lease l2(pool, routes, &s2);
    PeerRoutes::Lease l3(pool, routes, &s3);

    l1.release();
    ASSERT_EQ(pool.available(), 1u);

    PeerRoutes::Lease l4(pool, routes, &s4);
    ASSERT_EQ(l4.addr(), first); // only one free, so it comes back round
}

TEST(PeerRoutesRouteTable, LookupFindsTheLeasedSession)
{
    PeerRoutes::AddressPool pool(make_config());
    PeerRoutes::RouteTable routes;
    FakeSession s1, s2;

    PeerRoutes::Lease l1(pool, routes, &s1);
    PeerRoutes::Lease l2(pool, routes, &s2);

    ASSERT_EQ(routes.lookup(l1.addr()), &s1);
    ASSERT_EQ(routes.lookup(l2.addr()), &s2);
}

TEST(PeerRoutesRouteTable, LookupReturnsNullForUnleasedAddress)
{
    PeerRoutes::AddressPool pool(make_config());
    PeerRoutes::RouteTable routes;
    FakeSession s1;
    PeerRoutes::Lease l1(pool, routes, &s1);

    ASSERT_EQ(routes.lookup(IP::Addr::from_string("10.8.0.99")), nullptr);
}

TEST(PeerRoutesLease, ReleaseDropsBothTheRouteAndThePoolEntry)
{
    PeerRoutes::AddressPool pool(make_config());
    PeerRoutes::RouteTable routes;
    FakeSession s1;

    PeerRoutes::Lease lease(pool, routes, &s1);
    const IP::Addr addr = lease.addr();
    ASSERT_EQ(pool.available(), 251u);

    lease.release();

    ASSERT_EQ(routes.lookup(addr), nullptr);
    ASSERT_EQ(routes.size(), 0u);
    ASSERT_EQ(pool.available(), 252u);
}

TEST(PeerRoutesLease, ReleaseIsIdempotent)
{
    // Teardown paths may run more than once; a second release must not
    // return the address to the pool twice and inflate it past its size.
    PeerRoutes::AddressPool pool(make_config());
    PeerRoutes::RouteTable routes;
    FakeSession s1;

    PeerRoutes::Lease lease(pool, routes, &s1);
    lease.release();
    lease.release();

    ASSERT_EQ(pool.available(), 252u);
    ASSERT_FALSE(static_cast<bool>(lease));
}

TEST(PeerRoutesLease, DestructorReleasesWithoutAnExplicitCall)
{
    // The reason the type exists: no teardown path has to remember.
    PeerRoutes::AddressPool pool(make_config());
    PeerRoutes::RouteTable routes;
    FakeSession s1;
    IP::Addr addr;

    {
        PeerRoutes::Lease lease(pool, routes, &s1);
        addr = lease.addr();
        ASSERT_EQ(routes.lookup(addr), &s1);
    }

    ASSERT_EQ(routes.lookup(addr), nullptr);
    ASSERT_EQ(pool.available(), 252u);
}

TEST(PeerRoutesLease, MoveTransfersOwnershipExactlyOnce)
{
    PeerRoutes::AddressPool pool(make_config());
    PeerRoutes::RouteTable routes;
    FakeSession s1;
    IP::Addr addr;

    {
        PeerRoutes::Lease src(pool, routes, &s1);
        addr = src.addr();
        PeerRoutes::Lease dst(std::move(src));

        ASSERT_FALSE(static_cast<bool>(src));
        ASSERT_TRUE(static_cast<bool>(dst));
        ASSERT_EQ(dst.addr(), addr);

        // src going out of scope with dst still alive must not release.
        ASSERT_EQ(routes.lookup(addr), &s1);
    }

    ASSERT_EQ(routes.lookup(addr), nullptr);
    ASSERT_EQ(pool.available(), 252u);
}

TEST(PeerRoutesLease, MoveAssignmentReleasesWhatItOverwrites)
{
    PeerRoutes::AddressPool pool(make_config());
    PeerRoutes::RouteTable routes;
    FakeSession s1, s2;

    PeerRoutes::Lease a(pool, routes, &s1);
    const IP::Addr overwritten = a.addr();
    PeerRoutes::Lease b(pool, routes, &s2);
    ASSERT_EQ(pool.available(), 250u);

    a = std::move(b);

    ASSERT_EQ(routes.lookup(overwritten), nullptr);
    ASSERT_EQ(pool.available(), 251u);
    ASSERT_EQ(routes.size(), 1u);
}

TEST(PeerRoutesLease, AddressStaysReadableAfterRelease)
{
    // stop() reports the disconnect to the embedder using this address, and
    // may do so after the lease has already been given back.
    PeerRoutes::AddressPool pool(make_config());
    PeerRoutes::RouteTable routes;
    FakeSession s1;

    PeerRoutes::Lease lease(pool, routes, &s1);
    const IP::Addr addr = lease.addr();
    lease.release();

    ASSERT_EQ(lease.addr(), addr);
}

/// PROPERTY: no two leases held at the same time hold the same address.
/// @warning Expected to FAIL against current production: IP::Addr::operator++ leaves an
///  unspecified address unchanged, so AddressPool's constructor fills its free list with
///  pool_size copies of one address and hands the same one to every lease.
RC_GTEST_PROP(PeerRoutesPool, SimultaneousLeasesHoldDistinctAddresses, ())
{
    const auto lease_count = *rc::gen::inRange(size_t{2}, size_t{6}).as("simultaneous leases");

    // An unspecified start is what made every lease share one address; the pool
    // now refuses it outright, so the property below is over a valid pool.
    PeerRoutes::Config bad;
    bad.pool_start = IP::Addr();
    bad.pool_size = static_cast<unsigned int>(lease_count);
    RC_ASSERT_THROWS(PeerRoutes::AddressPool{bad});

    PeerRoutes::AddressPool pool(make_config(static_cast<unsigned int>(lease_count)));
    PeerRoutes::RouteTable routes;
    std::vector<FakeSession> sessions(lease_count);

    std::vector<PeerRoutes::Lease> leases;
    leases.reserve(sessions.size());
    for (auto &session : sessions)
    {
        leases.emplace_back(pool, routes, &session);
    }

    std::set<IP::Addr> distinct;
    for (const auto &lease : leases)
    {
        distinct.insert(lease.addr());
    }

    RC_ASSERT(distinct.size() == leases.size());
}

/// PROPERTY: while a lease is alive, the route table resolves its address to the session that holds it.
/// @warning Expected to FAIL against current production: RouteTable::add assigns into by_addr_,
///  so a second lease on an address already routed silently replaces the first session's route.
RC_GTEST_PROP(PeerRoutesRouteTable, EveryLiveLeaseIsRoutedToItsOwnSession, ())
{
    const auto pool_size = *rc::gen::inRange(size_t{1}, size_t{4}).as("addresses per pool");

    // Two pools over the same start hand out the same address sequence, so each address
    // reaches the shared table twice without any address being unspecified.
    PeerRoutes::AddressPool pool_a(make_config(static_cast<unsigned int>(pool_size)));
    PeerRoutes::AddressPool pool_b(make_config(static_cast<unsigned int>(pool_size)));
    PeerRoutes::RouteTable routes;
    std::vector<FakeSession> sessions(pool_size * 2);

    std::vector<PeerRoutes::Lease> leases;
    leases.reserve(sessions.size());
    for (size_t i = 0; i < pool_size; ++i)
    {
        leases.emplace_back(pool_a, routes, &sessions[2 * i]);
        // The second pool hands out an address the table already routes. That
        // used to overwrite the first session's route silently, stranding it.
        RC_ASSERT_THROWS(PeerRoutes::Lease(pool_b, routes, &sessions[(2 * i) + 1]));
    }

    for (size_t i = 0; i < leases.size(); ++i)
    {
        RC_ASSERT(routes.lookup(leases[i].addr()) == &sessions[2 * i]);
    }
}

/// PROPERTY: once the pool is exhausted, released addresses are handed back out in the order they were released.
RC_GTEST_PROP(PeerRoutesPool, ReleasedAddressesAreReservedInReleaseOrder, ())
{
    const auto pool_size = *rc::gen::inRange(size_t{2}, size_t{7}).as("pool size");

    PeerRoutes::AddressPool pool(make_config(static_cast<unsigned int>(pool_size)));
    PeerRoutes::RouteTable routes;
    std::vector<FakeSession> sessions(pool_size * 2);

    std::vector<PeerRoutes::Lease> leases;
    leases.reserve(pool_size);
    for (size_t i = 0; i < pool_size; ++i)
    {
        leases.emplace_back(pool, routes, &sessions[i]);
    }

    const auto release_order = *rc::genIndexPermutation(pool_size).as("release order");
    const auto release_count = *rc::gen::inRange(size_t{2}, pool_size + 1).as("addresses released");

    std::deque<IP::Addr> freed;
    for (size_t i = 0; i < release_count; ++i)
    {
        const auto index = release_order[i];
        freed.push_back(leases[index].addr());
        leases[index].release();
    }

    // Held to the end of the property: a reacquired address returned early would go back
    // to the free list and change the order under test.
    std::vector<PeerRoutes::Lease> reacquired;
    reacquired.reserve(release_count);
    for (size_t i = 0; i < release_count; ++i)
    {
        reacquired.emplace_back(pool, routes, &sessions[pool_size + i]);
        RC_ASSERT(reacquired.back().addr() == freed[i]);
    }
}
