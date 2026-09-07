//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2024- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#include "test_common.hpp"
#include "test_generators.hpp"

#include <openvpn/addr/addrpair.hpp>

#include <string>

TEST(AddrMaskPairStringPair, DefaultConstructedIsEmpty)
{
    const openvpn::IP::AddrMaskPair::StringPair empty;

    EXPECT_EQ(empty.size(), 0U);
    EXPECT_TRUE(empty.render().empty());
    EXPECT_TRUE(empty[0].empty());
    EXPECT_TRUE(empty[1].empty());
}

/// PROPERTY: for any string, the one-string constructor yields size 1, renders the string bare and exposes it at index 0 with an empty second slot.
RC_GTEST_PROP(AddrMaskPairStringPair, OneStringConstructorHoldsIt, (const std::string &first))
{
    const openvpn::IP::AddrMaskPair::StringPair one(first);

    RC_ASSERT(one.size() == 1U);
    RC_ASSERT(one.render() == first);
    RC_ASSERT(one[0] == first);
    RC_ASSERT(one[1].empty());
}

/// PROPERTY: for any two strings, the two-string constructor yields size 2, renders them slash-joined and exposes them in order.
RC_GTEST_PROP(AddrMaskPairStringPair, TwoStringConstructorHoldsBoth, (const std::string &first, const std::string &second))
{
    const openvpn::IP::AddrMaskPair::StringPair two(first, second);

    RC_ASSERT(two.size() == 2U);
    RC_ASSERT(two.render() == first + "/" + second);
    RC_ASSERT(two[0] == first);
    RC_ASSERT(two[1] == second);
}

RC_GTEST_PROP(AddrMaskPairStringPair, SupportsPush, (const std::string &first, const std::string &second))
{
    openvpn::IP::AddrMaskPair::StringPair empty;
    empty.push_back(*rc::gen::string<std::string>());
    RC_ASSERT(empty.size() == 1U);
    empty.push_back(*rc::gen::string<std::string>());
    RC_ASSERT(empty.size() == 2U);

    openvpn::IP::AddrMaskPair::StringPair one(first);
    one.push_back(*rc::gen::string<std::string>());
    RC_ASSERT(one.size() == 2U);
}

RC_GTEST_PROP(AddrMaskPairStringPair, PushingMoreThanPairThrows, (const std::string &first, const std::string &second))
{
    openvpn::IP::AddrMaskPair::StringPair pushed;
    pushed.push_back(first);
    pushed.push_back(second);
    RC_ASSERT_THROWS_AS(pushed.push_back(*rc::gen::string<std::string>()), openvpn::IP::AddrMaskPair::StringPair::addr_pair_string_error);
}

RC_GTEST_PROP(AddrMaskPairStringPair, AccessingOutsidePairThrows, (const std::string &first, const std::string &second))
{
    openvpn::IP::AddrMaskPair::StringPair non_const_pair(first, second);
    const openvpn::IP::AddrMaskPair::StringPair const_pair(first, second);
    const int index = *rc::gen::suchThat<int>([](const int i)
                                              { return i < 0 || i > 2; });

    RC_ASSERT_THROWS_AS(non_const_pair[index], openvpn::IP::AddrMaskPair::StringPair::addr_pair_string_error);
    RC_ASSERT_THROWS_AS(const_pair[index], openvpn::IP::AddrMaskPair::StringPair::addr_pair_string_error);
}
