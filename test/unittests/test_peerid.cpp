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

// Unit tests for PeerId::Table (openvpn/server/peerid.hpp).
//
// The behaviours worth pinning are the two the previous monotonic counter did
// not have: ids come back when a session ends, and no id can leave the 24-bit
// wire field. Both are structural in OpenVPN 2 -- the id is an index into a
// max_clients-sized array -- and these assert we reproduced that rather than
// re-deriving something adjacent.

#include "test_common.hpp"

#include <openvpn/server/peerid.hpp>

using namespace openvpn;

TEST(PeerIdTable, IdsStartAtZeroAndAscend)
{
    PeerId::Table<int> t(4);
    ASSERT_EQ(t.acquire(10).value(), 0);
    ASSERT_EQ(t.acquire(11).value(), 1);
    ASSERT_EQ(t.acquire(12).value(), 2);
    ASSERT_EQ(t.in_use(), 3u);
}

// The whole point of the slot table: ending a session returns its id. A
// counter never did, which is how a long-lived server walked past the wire
// field.
TEST(PeerIdTable, ReleasedIdsComeBack)
{
    PeerId::Table<int> t(3);
    ASSERT_EQ(t.acquire(10).value(), 0);
    ASSERT_EQ(t.acquire(11).value(), 1);
    ASSERT_EQ(t.acquire(12).value(), 2);
    ASSERT_FALSE(t.acquire(13).has_value());

    t.release(1);
    ASSERT_EQ(t.in_use(), 2u);
    ASSERT_EQ(t.acquire(14).value(), 1);
    ASSERT_EQ(t.in_use(), 3u);
}

// Lowest free slot, matching v2's multi_assign_peer_id() linear scan, not
// round-robin or most-recently-freed.
TEST(PeerIdTable, ReuseTakesTheLowestFreeSlot)
{
    PeerId::Table<int> t(4);
    for (int i = 0; i < 4; ++i)
        ASSERT_TRUE(t.acquire(i).has_value());

    t.release(3);
    t.release(1);
    ASSERT_EQ(t.acquire(99).value(), 1);
    ASSERT_EQ(t.acquire(98).value(), 3);
}

TEST(PeerIdTable, ExhaustionIsReportedNotWrapped)
{
    PeerId::Table<int> t(2);
    ASSERT_TRUE(t.acquire(1).has_value());
    ASSERT_TRUE(t.acquire(2).has_value());
    ASSERT_FALSE(t.acquire(3).has_value());
    // Still refused after a failed attempt; nothing was consumed by it.
    ASSERT_EQ(t.in_use(), 2u);
    ASSERT_FALSE(t.acquire(4).has_value());
}

// The bound is the reason the type exists: max_clients is checked once, so no
// individual allocation can produce an id that will not fit the header.
TEST(PeerIdTable, CapacityBeyondTheWireFieldIsRefused)
{
    ASSERT_THROW(PeerId::Table<int>(static_cast<std::size_t>(PeerId::UNDEF)), Exception);
    ASSERT_THROW(PeerId::Table<int>(static_cast<std::size_t>(PeerId::UNDEF) + 1), Exception);
    // One below the reserved value is the largest usable table.
    ASSERT_NO_THROW(PeerId::Table<int>(static_cast<std::size_t>(PeerId::UNDEF) - 1));
}

TEST(PeerIdTable, EveryIssuedIdFitsTheWireField)
{
    PeerId::Table<int> t(64);
    for (int i = 0; i < 64; ++i)
    {
        const auto id = t.acquire(i);
        ASSERT_TRUE(id.has_value());
        ASSERT_GE(*id, 0);
        ASSERT_LT(*id, PeerId::UNDEF);
    }
}

TEST(PeerIdTable, FindResolvesOnlyIssuedIds)
{
    PeerId::Table<int> t(4);
    const int id = t.acquire(42).value();
    ASSERT_NE(t.find(id), nullptr);
    ASSERT_EQ(*t.find(id), 42);

    t.release(id);
    ASSERT_EQ(t.find(id), nullptr);
    // Out of range in both directions.
    ASSERT_EQ(t.find(-1), nullptr);
    ASSERT_EQ(t.find(4), nullptr);
    ASSERT_EQ(t.find(1 << 20), nullptr);
}

// Peer float keeps the id and moves the endpoint, so update() must not disturb
// the allocation.
TEST(PeerIdTable, UpdateRepointsWithoutReallocating)
{
    PeerId::Table<int> t(4);
    const int id = t.acquire(100).value();
    t.update(id, 200);
    ASSERT_EQ(*t.find(id), 200);
    ASSERT_EQ(t.in_use(), 1u);
    // A fresh acquire must not collide with the still-held id.
    ASSERT_NE(t.acquire(300).value(), id);
}

TEST(PeerIdTable, UpdateAndReleaseIgnoreIdsThatWereNeverIssued)
{
    PeerId::Table<int> t(4);
    // Teardown paths call release() unconditionally, including for a session
    // that never got an id (peer_id defaults to -1), so this must be inert.
    ASSERT_NO_THROW(t.release(-1));
    ASSERT_NO_THROW(t.release(0));
    ASSERT_NO_THROW(t.release(999));
    ASSERT_NO_THROW(t.update(-1, 5));
    ASSERT_NO_THROW(t.update(999, 5));
    ASSERT_EQ(t.in_use(), 0u);

    // Double release of a real id must not corrupt the count either.
    const int id = t.acquire(7).value();
    t.release(id);
    t.release(id);
    ASSERT_EQ(t.in_use(), 0u);
    ASSERT_EQ(t.acquire(8).value(), id);
}

TEST(PeerIdTable, ClearReleasesEverything)
{
    PeerId::Table<int> t(3);
    t.acquire(1);
    t.acquire(2);
    t.clear();
    ASSERT_EQ(t.in_use(), 0u);
    ASSERT_EQ(t.find(0), nullptr);
    ASSERT_EQ(t.acquire(9).value(), 0);
}

// A zero-capacity table is what the transports hold before start() sizes them;
// it must refuse rather than hand out an out-of-range index.
TEST(PeerIdTable, ZeroCapacityIssuesNothing)
{
    PeerId::Table<int> t(0);
    ASSERT_EQ(t.max_supported_slots(), 0u);
    ASSERT_FALSE(t.acquire(1).has_value());
    ASSERT_EQ(t.find(0), nullptr);
}
