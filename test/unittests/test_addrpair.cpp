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

#include <array>
#include <cstddef>
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

/// PROPERTY: for any two strings, constructing with the first and pushing the second equals constructing with both.
RC_GTEST_PROP(AddrMaskPairStringPair, PushAfterOneEqualsConstructingWithBoth, (const std::string &first, const std::string &second))
{
    openvpn::IP::AddrMaskPair::StringPair pushed(first);
    pushed.push_back(second);

    const openvpn::IP::AddrMaskPair::StringPair constructed(first, second);
    RC_ASSERT(pushed.size() == constructed.size());
    RC_ASSERT(pushed[0] == constructed[0]);
    RC_ASSERT(pushed[1] == constructed[1]);
}

/// PROPERTY: for any two strings, pushing both onto an empty pair equals constructing with both.
RC_GTEST_PROP(AddrMaskPairStringPair, TwoPushesEqualConstructingWithBoth, (const std::string &first, const std::string &second))
{
    openvpn::IP::AddrMaskPair::StringPair pushed;
    pushed.push_back(first);
    pushed.push_back(second);

    const openvpn::IP::AddrMaskPair::StringPair constructed(first, second);
    RC_ASSERT(pushed.size() == constructed.size());
    RC_ASSERT(pushed[0] == constructed[0]);
    RC_ASSERT(pushed[1] == constructed[1]);
}

/// PROPERTY: for any two-string pair, slot and replacement, assigning through the subscript is visible in render().
RC_GTEST_PROP(AddrMaskPairStringPair, SubscriptAssignmentRenders, (const std::string &first, const std::string &second, const std::string &replacement))
{
    openvpn::IP::AddrMaskPair::StringPair two(first, second);
    std::array<std::string, 2> expected{first, second};
    const auto slot = *rc::gen::inRange<std::size_t>(0, 2).as("slot");

    two[slot] = replacement;
    expected[slot] = replacement;

    RC_ASSERT(two.render() == expected[0] + "/" + expected[1]);
}

/// PROPERTY: for any full pair and third string, push_back throws addr_pair_string_error and leaves the pair unchanged.
RC_GTEST_PROP(AddrMaskPairStringPair, PushingMoreThanPairThrows, (const std::string &first, const std::string &second, const std::string &third))
{
    openvpn::IP::AddrMaskPair::StringPair full(first, second);

    RC_ASSERT_THROWS_AS(full.push_back(third), openvpn::IP::AddrMaskPair::StringPair::addr_pair_string_error);
    RC_ASSERT(full.size() == 2U);
    RC_ASSERT(full[0] == first);
    RC_ASSERT(full[1] == second);
}

/// PROPERTY: for any index at or beyond 2, both subscript overloads throw addr_pair_string_error.
RC_GTEST_PROP(AddrMaskPairStringPair, SubscriptBeyondPairThrows, (const std::string &first, const std::string &second))
{
    openvpn::IP::AddrMaskPair::StringPair mutable_pair(first, second);
    const openvpn::IP::AddrMaskPair::StringPair const_pair(first, second);
    const auto index = *rc::gen::inRange<std::size_t>(2, 64).as("index at or beyond the pair");

    RC_ASSERT_THROWS_AS(mutable_pair[index], openvpn::IP::AddrMaskPair::StringPair::addr_pair_string_error);
    RC_ASSERT_THROWS_AS(const_pair[index], openvpn::IP::AddrMaskPair::StringPair::addr_pair_string_error);
}

/// PROPERTY: for any well-formed input, from_string yields a pair whose two members carry the version the address was drawn for.
RC_GTEST_PROP(AddrMaskPair, FromStringYieldsPairOfInputVersion, (const openvpn::IP::Addr::Version version))
{
    const auto input = *rc::genAddrMaskPairString(version).as("well-formed input");

    const auto parsed = openvpn::IP::AddrMaskPair::from_string(input);

    RC_ASSERT(parsed.version() == version);
}

/// PROPERTY: for any well-formed input, the parsed netmask is exactly the netmask of its own prefix length — the round-trip identity of two ip.hpp primitives that from_string_impl calls only one half of.
RC_GTEST_PROP(AddrMaskPair, FromStringYieldsContiguousNetmask, (const openvpn::IP::Addr::Version version))
{
    const auto input = *rc::genAddrMaskPairString(version).as("well-formed input");

    const auto parsed = openvpn::IP::AddrMaskPair::from_string(input);

    const auto prefix_len = parsed.netmask.prefix_len();
    RC_ASSERT(parsed.netmask == openvpn::IP::Addr::netmask_from_prefix_len(version, prefix_len));
}

/// PROPERTY: for any valid address, the bare form parses to that address with an all-ones netmask.
RC_GTEST_PROP(AddrMaskPair, BareAddressYieldsAllOnesNetmask, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");

    const auto parsed = openvpn::IP::AddrMaskPair::from_string(address);

    RC_ASSERT(parsed.addr == openvpn::IP::Addr::from_string(address));
    RC_ASSERT(parsed.netmask.prefix_len() == openvpn::IP::Addr::version_size(version));
}

/// PROPERTY: for any malformed input, from_string throws addr_pair_mask_parse_error and nothing else.
RC_GTEST_PROP(AddrMaskPair, FromStringRejectsMalformedInput, (const openvpn::IP::Addr::Version version))
{
    const auto input = *rc::genAddrMaskPairString(version, false).as("malformed input");

    RC_ASSERT_THROWS_AS(openvpn::IP::AddrMaskPair::from_string(input), openvpn::IP::AddrMaskPair::addr_pair_mask_parse_error);
}

/// PROPERTY: for any non-empty malformed input, the rejection diagnostic quotes the input verbatim.
RC_GTEST_PROP(AddrMaskPair, RejectionQuotesInput, (const openvpn::IP::Addr::Version version))
{
    // one malformed shape in seven is the empty string, which has nothing to quote
    const auto input = *rc::gen::nonEmpty(rc::genAddrMaskPairString(version, false)).as("non-empty malformed input");

    const auto rejection = rc::helpers::rejectionMessage(input);

    RC_ASSERT(rejection.has_value());
    RC_ASSERT(rejection->find(input) != std::string::npos); // NOLINT(bugprone-unchecked-optional-access) -- guarded by the RC_ASSERT above
}

/// PROPERTY: for any malformed input and any title, the rejection diagnostic quotes the title.
RC_GTEST_PROP(AddrMaskPair, RejectionQuotesTitle, (const openvpn::IP::Addr::Version version))
{
    const auto input = *rc::genAddrMaskPairString(version, false).as("malformed input");
    const auto title = *rc::gen::nonEmpty(rc::string_from_allowed_chars(rc::ALPHA_CHARACTERS)).as("title");

    const auto rejection = rc::helpers::rejectionMessage(input, title.c_str());

    RC_ASSERT(rejection.has_value());
    RC_ASSERT(rejection->find(title) != std::string::npos); // NOLINT(bugprone-unchecked-optional-access) -- guarded by the RC_ASSERT above
}

/// PROPERTY: for any valid address and rejected mask term, the two-string overload's diagnostic quotes both terms slash-joined.
RC_GTEST_PROP(AddrMaskPair, TwoStringOverloadRejectionQuotesBothTerms, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");
    const auto mask = *rc::genMaskToken(version, false).as("rejected mask term");

    const auto rejection = rc::helpers::rejectionMessageForTerms(address, mask);

    RC_ASSERT(rejection.has_value());
    RC_ASSERT(rejection->find(address + "/" + mask) != std::string::npos); // NOLINT(bugprone-unchecked-optional-access) -- guarded by the RC_ASSERT above
}

/// PROPERTY: for any valid address and rejected mask term, the StringPair overload's diagnostic quotes both terms slash-joined.
RC_GTEST_PROP(AddrMaskPair, StringPairOverloadRejectionQuotesBothTerms, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");
    const auto mask = *rc::genMaskToken(version, false).as("rejected mask term");

    const auto rejection = rc::helpers::rejectionMessage(openvpn::IP::AddrMaskPair::StringPair(address, mask));

    RC_ASSERT(rejection.has_value());
    RC_ASSERT(rejection->find(address + "/" + mask) != std::string::npos); // NOLINT(bugprone-unchecked-optional-access) -- guarded by the RC_ASSERT above
}

/// A size-0 StringPair is the one shape reachable only through the StringPair overload; there is nothing to draw, so this is an example rather than a property.
TEST(AddrMaskPair, FromStringRejectsEmptyStringPair)
{
    EXPECT_THROW(openvpn::IP::AddrMaskPair::from_string(openvpn::IP::AddrMaskPair::StringPair()), openvpn::IP::AddrMaskPair::addr_pair_mask_parse_error);
}

/// PROPERTY: for any pair whose members share a version, version() reports that version.
RC_GTEST_PROP(AddrMaskPair, VersionReportsSharedMemberVersion, (const openvpn::IP::Addr::Version version))
{
    const auto pair = *rc::genAddrMaskPair(version).as("pair");

    RC_ASSERT(pair.version() == version);
}

/// PROPERTY: for any pair assembled member by member from different versions, as tun/mac/gw.hpp does, version() reports UNSPEC.
RC_GTEST_PROP(AddrMaskPair, VersionReportsUnspecForMismatchedMembers, (const openvpn::IP::Addr::Version address_version))
{
    const auto netmask_version = rc::helpers::otherVersion(address_version);
    const openvpn::IP::AddrMaskPair mismatched{
        .addr = *rc::genIPAddr(address_version).as("address"),
        .netmask = openvpn::IP::Addr::netmask_from_prefix_len(netmask_version, *rc::genPrefixLength(netmask_version).as("prefix length of the other version"))};

    RC_ASSERT(mismatched.version() == openvpn::IP::Addr::UNSPEC);
}

/// PROPERTY: for any valid pair, parsing its prefix-length rendering restores both members.
RC_GTEST_PROP(AddrMaskPair, ParsingPrefixRenderingRestoresBothMembers, (const openvpn::IP::AddrMaskPair &original))
{
    const auto restored = openvpn::IP::AddrMaskPair::from_string(original.to_string(false));

    RC_ASSERT(restored.addr == original.addr);
    RC_ASSERT(restored.netmask == original.netmask);
}
