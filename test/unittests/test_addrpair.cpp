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
#include <cstdint>
#include <limits>
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

/// PROPERTY: for any valid pair, parsing its netmask rendering restores both members.
RC_GTEST_PROP(AddrMaskPair, ParsingNetmaskRenderingRestoresBothMembers, (const openvpn::IP::AddrMaskPair &original))
{
    const auto restored = openvpn::IP::AddrMaskPair::from_string(original.to_string(true));

    RC_ASSERT(restored.addr == original.addr);
    RC_ASSERT(restored.netmask == original.netmask);
}

/// PROPERTY: for any valid address and accepted mask term, the two-string overload yields the same members as the joined-string form.
RC_GTEST_PROP(AddrMaskPair, TwoStringOverloadAgreesWithJoinedForm, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");
    const auto mask = *rc::genMaskToken(version).as("accepted mask term");

    const auto from_joined = openvpn::IP::AddrMaskPair::from_string(address + "/" + mask);
    const auto from_two_strings = openvpn::IP::AddrMaskPair::from_string(address, mask);

    RC_ASSERT(from_two_strings.addr == from_joined.addr);
    RC_ASSERT(from_two_strings.netmask == from_joined.netmask);
}

/// PROPERTY: for any well-formed joined input, the two-string overload with an empty second string yields the same members as the single-string overload.
RC_GTEST_PROP(AddrMaskPair, EmptySecondStringDefersToJoinedForm, (const openvpn::IP::Addr::Version version))
{
    const auto input = *rc::genAddrMaskPairString(version).as("well-formed input");

    // a literal "" would bind to the title parameter of the single-string overload
    const std::string no_mask;

    const auto from_joined = openvpn::IP::AddrMaskPair::from_string(input);
    const auto from_two_strings = openvpn::IP::AddrMaskPair::from_string(input, no_mask);

    RC_ASSERT(from_two_strings.addr == from_joined.addr);
    RC_ASSERT(from_two_strings.netmask == from_joined.netmask);
}

/// PROPERTY: for any valid address and accepted mask term, the StringPair overload yields the same members as the joined-string form.
RC_GTEST_PROP(AddrMaskPair, StringPairOverloadAgreesWithJoinedForm, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");
    const auto mask = *rc::genMaskToken(version).as("accepted mask term");

    const auto from_joined = openvpn::IP::AddrMaskPair::from_string(address + "/" + mask);
    const auto from_string_pair = openvpn::IP::AddrMaskPair::from_string(openvpn::IP::AddrMaskPair::StringPair(address, mask));

    RC_ASSERT(from_string_pair.addr == from_joined.addr);
    RC_ASSERT(from_string_pair.netmask == from_joined.netmask);
}

/// PROPERTY: for any valid address, the bare address yields the same members as the address with an empty mask term.
RC_GTEST_PROP(AddrMaskPair, BareAddressAgreesWithEmptyMaskTerm, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");

    const auto from_bare_address = openvpn::IP::AddrMaskPair::from_string(address);
    const auto from_empty_mask_term = openvpn::IP::AddrMaskPair::from_string(address + "/");

    RC_ASSERT(from_bare_address.addr == from_empty_mask_term.addr);
    RC_ASSERT(from_bare_address.netmask == from_empty_mask_term.netmask);
}

/// PROPERTY: for any valid address and rejected mask term, the two-string overload throws addr_pair_mask_parse_error — the catch block tunprop.hpp relies on with get_optional.
RC_GTEST_PROP(AddrMaskPair, TwoStringOverloadRejectsMalformedMaskTerm, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");
    const auto mask = *rc::genMaskToken(version, false).as("rejected mask term");

    RC_ASSERT_THROWS_AS(openvpn::IP::AddrMaskPair::from_string(address, mask), openvpn::IP::AddrMaskPair::addr_pair_mask_parse_error);
}

/// PROPERTY: for any valid address and rejected mask term, the StringPair overload throws addr_pair_mask_parse_error.
RC_GTEST_PROP(AddrMaskPair, StringPairOverloadRejectsMalformedMaskTerm, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");
    const auto mask = *rc::genMaskToken(version, false).as("rejected mask term");

    RC_ASSERT_THROWS_AS(openvpn::IP::AddrMaskPair::from_string(openvpn::IP::AddrMaskPair::StringPair(address, mask)), openvpn::IP::AddrMaskPair::addr_pair_mask_parse_error);
}

/// PROPERTY: for any pair, clearing the host bits of its address yields a canonical pair.
RC_GTEST_PROP(AddrMaskPair, MaskedAddressIsCanonical, (const openvpn::IP::AddrMaskPair &pair))
{
    const openvpn::IP::AddrMaskPair masked{.addr = pair.addr & pair.netmask, .netmask = pair.netmask};

    RC_ASSERT(masked.is_canonical());
}

/// PROPERTY: for any pair whose address has a host bit set, is_canonical() is false.
RC_GTEST_PROP(AddrMaskPair, AddressWithHostBitIsNotCanonical, (const openvpn::IP::Addr::Version version))
{
    const auto pair = *rc::genNonCanonicalAddrMaskPair(version).as("pair with a host bit set");

    RC_ASSERT_FALSE(pair.is_canonical());
}

/// PROPERTY: for any valid address and legal prefix length, the same prefix length written with 2^32 added is rejected.
/// @warning Expected to FAIL against current production: parse_number accumulates digits without an overflow
///          check, so a prefix length at or above 2^32 wraps modulo 2^32 before netmask_from_prefix_len's range guard sees it.
RC_GTEST_PROP(AddrMaskPair, DefectOverlongPrefixLengthIsRejected, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");
    const auto legal = *rc::genPrefixLength(version).as("legal prefix length");
    const auto unsigned_int_modulus = static_cast<std::uint64_t>(std::numeric_limits<unsigned int>::max()) + 1;
    const auto wrapped = std::to_string(legal + unsigned_int_modulus);

    // control: the same address and prefix parse, so a failure below is the wrap and not the setup
    openvpn::IP::AddrMaskPair::from_string(address + "/" + std::to_string(legal));

    RC_ASSERT_THROWS_AS(openvpn::IP::AddrMaskPair::from_string(address + "/" + wrapped), openvpn::IP::AddrMaskPair::addr_pair_mask_parse_error);
}

/// PROPERTY: for any valid address and legal prefix length, the numeric and dotted-netmask spellings of that mask parse to the same pair — from_string_impl reaches them through disjoint branches that nothing else compares.
RC_GTEST_PROP(AddrMaskPair, PrefixAndNetmaskSpellingsAgree, (const openvpn::IP::Addr::Version version))
{
    const auto address = *rc::genIPAddressString(version).as("address");
    const auto prefix_len = *rc::genPrefixLength(version).as("prefix length");
    const auto dotted = openvpn::IP::Addr::netmask_from_prefix_len(version, prefix_len).to_string();

    const auto from_prefix = openvpn::IP::AddrMaskPair::from_string(address + "/" + std::to_string(prefix_len));
    const auto from_netmask = openvpn::IP::AddrMaskPair::from_string(address + "/" + dotted);

    RC_ASSERT(from_netmask.addr == from_prefix.addr);
    RC_ASSERT(from_netmask.netmask == from_prefix.netmask);
}
