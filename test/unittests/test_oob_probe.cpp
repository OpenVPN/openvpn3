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

#include "test_common.hpp"

#include <cstdint>
#include <cstring>

#include <gtest/gtest.h>

#include <openvpn/buffer/buffer.hpp>

#include <openvpn/ssl/oob_probe.hpp>

using namespace openvpn;

// A probe request round-trips: what we write, we read back identically.
TEST(OobProbe, ProbeRequestRoundtrip)
{
    const oob::ProbeRequest sent{
        .request_id = 0x0123456789abcdefULL,
        .timestamp = 0x1122334455667788ULL,
        .flags = oob::request_flag_probe_only,
    };

    BufferAllocated buf(128);
    ASSERT_TRUE(sent.write(buf));

    const auto out_opt = oob::probe_request_find(buf);
    ASSERT_TRUE(out_opt);
    const auto &out = *out_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(out.request_id, sent.request_id);
    EXPECT_EQ(out.timestamp, sent.timestamp);
    EXPECT_EQ(out.flags, sent.flags);
}

// A probe reply round-trips, request_id and all fields preserved.
TEST(OobProbe, ProbeReplyRoundtrip)
{
    const oob::ProbeReply sent{
        .request_id = 0x0123456789abcdefULL,
        .priority = 100,
        .weight = 50,
        .max_latency_diff = 25,
        .connect_lifetime = 60,
        .flags = oob::reply_flag_resend_wkc,
    };

    BufferAllocated buf(128);
    ASSERT_TRUE(sent.write(buf));

    const auto out_opt = oob::probe_reply_find(buf);
    ASSERT_TRUE(out_opt);
    const auto &out = *out_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(out.request_id, sent.request_id);
    EXPECT_EQ(out.priority, sent.priority);
    EXPECT_EQ(out.weight, sent.weight);
    EXPECT_EQ(out.connect_lifetime, sent.connect_lifetime);
    EXPECT_EQ(out.flags, sent.flags);
    EXPECT_EQ(out.max_latency_diff, sent.max_latency_diff);
}

// A remote's other addresses cannot be both the same server and distinct ones.
TEST(OobProbe, ReplyRejectsAddrsEqualWithProbeMore)
{
    const oob::ProbeReply sent{.flags = oob::reply_flag_addrs_equal | oob::reply_flag_probe_more};

    BufferAllocated buf(128);
    ASSERT_TRUE(sent.write(buf));

    EXPECT_FALSE(oob::probe_reply_find(buf));
}

// Sharing the connect_lifetime with the other addresses says nothing unless they
// have been declared the same server first.
TEST(OobProbe, ReplyRejectsLifetimeSharedWithoutAddrsEqual)
{
    const oob::ProbeReply sent{.flags = oob::reply_flag_lifetime_shared};

    BufferAllocated buf(128);
    ASSERT_TRUE(sent.write(buf));

    EXPECT_FALSE(oob::probe_reply_find(buf));
}

// Flag bits this version does not know are kept, not rejected, so that a reply
// from a future version still parses.
TEST(OobProbe, ReplyKeepsUnknownFlagBits)
{
    const oob::ProbeReply sent{.flags = 0x8000};

    BufferAllocated buf(128);
    ASSERT_TRUE(sent.write(buf));

    const auto out_opt = oob::probe_reply_find(buf);
    ASSERT_TRUE(out_opt);
    const auto &out = *out_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(out.flags, 0x8000);
}

// The legal combination of the two is accepted.
TEST(OobProbe, ReplyAcceptsLifetimeSharedWithAddrsEqual)
{
    const oob::ProbeReply sent{.flags = oob::reply_flag_addrs_equal | oob::reply_flag_lifetime_shared};

    BufferAllocated buf(128);
    ASSERT_TRUE(sent.write(buf));

    const auto out_opt = oob::probe_reply_find(buf);
    ASSERT_TRUE(out_opt);
    const auto &out = *out_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(out.flags, sent.flags);
}

// Wire format is locked (big-endian) so it stays interoperable with the C impl.
TEST(OobProbe, ProbeRequestWireFormat)
{
    const oob::ProbeRequest sent{
        .request_id = 0x0123456789abcdefULL,
        .timestamp = 0x1122334455667788ULL,
        .flags = oob::request_flag_probe_only,
    };

    BufferAllocated buf(128);
    ASSERT_TRUE(sent.write(buf));

    const unsigned char expected[] = {
        0x00,
        0x02, // TLV type 0x2 = probe request (not optional)
        0x00,
        0x14, // TLV value length = 20
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef, // request_id (BE)
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88, // timestamp (BE)
        0x00,
        0x00,
        0x00,
        0x01, // flags = request_flag_probe_only (BE)
    };
    ASSERT_EQ(buf.size(), sizeof(expected));
    EXPECT_EQ(std::memcmp(buf.c_data(), expected, sizeof(expected)), 0);
}

// The probe reply wire format is locked to the spec's field order
// (priority, weight, max_latency_diff, connect_lifetime, flags).
TEST(OobProbe, ProbeReplyWireFormat)
{
    const oob::ProbeReply sent{
        .request_id = 0x0123456789abcdefULL,
        .priority = 100,
        .weight = 50,
        .max_latency_diff = 25,
        .connect_lifetime = 60,
        .flags = oob::reply_flag_resend_wkc,
    };

    BufferAllocated buf(128);
    ASSERT_TRUE(sent.write(buf));

    const unsigned char expected[] = {
        0x00,
        0x03, // TLV type 0x3 = probe reply (not optional)
        0x00,
        0x12, // TLV value length = 18
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xab,
        0xcd,
        0xef, // request_id (BE)
        0x00,
        0x64, // priority = 100 (BE)
        0x00,
        0x32, // weight = 50 (BE)
        0x00,
        0x19, // max_latency_diff = 25 (BE)
        0x00,
        0x3c, // connect_lifetime = 60 (BE)
        0x00,
        0x01, // flags = reply_flag_resend_wkc (BE)
    };
    ASSERT_EQ(buf.size(), sizeof(expected));
    EXPECT_EQ(std::memcmp(buf.c_data(), expected, sizeof(expected)), 0);
}

// Unknown *optional* TLVs before the wanted one are skipped (forward compatibility).
TEST(OobProbe, SkipsUnknownOptionalTlv)
{
    BufferAllocated buf(128);
    // an unknown TLV (type 0x7ff, 3 bytes of value) marked optional, so skippable
    ASSERT_TRUE(oob::tlv_write_header(buf, 0x7ff, true, 3));
    ASSERT_TRUE(oob::write_u16(buf, 0xdead));
    buf.push_back(0xaa);
    // the real probe_parameter TLV
    const oob::ProbeRequest sent{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(sent.write(buf));

    const auto out_opt = oob::probe_request_find(buf);
    ASSERT_TRUE(out_opt);
    const auto &out = *out_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(out.timestamp, 42U);
}

// The optional flag is the *top* bit of the first 16-bit field, so an optional
// TLV is distinguishable on the wire and not just through our own constant.
TEST(OobProbe, OptionalFlagWirePosition)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::tlv_write_header(buf, 0x7ff, true, 0));

    const unsigned char expected[] = {
        0x87,
        0xff, // optional bit set, type 0x7ff
        0x00,
        0x00, // value length = 0
    };
    ASSERT_EQ(buf.size(), sizeof(expected));
    EXPECT_EQ(std::memcmp(buf.c_data(), expected, sizeof(expected)), 0);
}

// A TLV of the type we want counts whether or not it is marked optional: the
// flag says what to do with a type we do not know, not which types to look at.
TEST(OobProbe, FindsWantedTlvMarkedOptional)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::tlv_write_header(buf, oob::tlv_probe_request, true, oob::ProbeRequest::wire_len));
    ASSERT_TRUE(oob::write_u64(buf, 11)); // request_id
    ASSERT_TRUE(oob::write_u64(buf, 22)); // timestamp
    ASSERT_TRUE(oob::write_u32(buf, 0));  // flags

    const auto out_opt = oob::probe_request_find(buf);
    ASSERT_TRUE(out_opt);
    const auto &out = *out_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(out.request_id, 11U);
}

// A header is never written without room for the value it promises, so a failed
// write leaves no partial TLV for a following one to be appended to.
TEST(OobProbe, HeaderNotWrittenWithoutRoomForValue)
{
    // room for the header, but not for the value it promises
    constexpr std::size_t capacity = 2 * oob::tlv_header_len;
    constexpr std::size_t value_len = 16;

    BufferAllocated buf(capacity);
    EXPECT_FALSE(oob::tlv_write_header(buf, oob::tlv_probe_request, false, value_len));
    EXPECT_EQ(buf.size(), 0U);
}

// The same message is rejected when that TLV is not marked optional: we cannot
// act on a message carrying something mandatory we do not understand.
TEST(OobProbe, RejectsUnknownMandatoryTlv)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::tlv_write_header(buf, 0x7ff, false, 3));
    ASSERT_TRUE(oob::write_u16(buf, 0xdead));
    buf.push_back(0xaa);
    const oob::ProbeRequest sent{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(sent.write(buf));

    EXPECT_FALSE(oob::probe_request_find(buf));
}

// ... and equally when that TLV sits *after* the one we were looking for.
TEST(OobProbe, RejectsUnknownMandatoryTlvAfterWanted)
{
    BufferAllocated buf(128);
    const oob::ProbeRequest sent{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(sent.write(buf));
    ASSERT_TRUE(oob::tlv_write_header(buf, 0x7ff, false, 3));
    ASSERT_TRUE(oob::write_u16(buf, 0xdead));
    buf.push_back(0xaa);

    EXPECT_FALSE(oob::probe_request_find(buf));
}

// An unknown *optional* TLV after the wanted one is skipped, not tripped over.
TEST(OobProbe, SkipsUnknownOptionalTlvAfterWanted)
{
    BufferAllocated buf(128);
    const oob::ProbeRequest sent{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(sent.write(buf));
    ASSERT_TRUE(oob::tlv_write_header(buf, 0x7ff, true, 3));
    ASSERT_TRUE(oob::write_u16(buf, 0xdead));
    buf.push_back(0xaa);

    const auto out_opt = oob::probe_request_find(buf);
    ASSERT_TRUE(out_opt);
    const auto &out = *out_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(out.timestamp, 42U);
}

// The probe TLV may appear only once; a second one is not something to choose
// between.
TEST(OobProbe, RejectsRepeatedProbeTlv)
{
    BufferAllocated buf(128);
    ASSERT_TRUE((oob::ProbeRequest{.timestamp = 42, .flags = 0}).write(buf));
    ASSERT_TRUE((oob::ProbeRequest{.timestamp = 43, .flags = 0}).write(buf));

    EXPECT_FALSE(oob::probe_request_find(buf));
}

// Trailing bytes too few to hold a TLV header are a truncated entry, not padding.
TEST(OobProbe, RejectsTrailingPartialHeader)
{
    BufferAllocated buf(128);
    const oob::ProbeRequest sent{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(sent.write(buf));
    ASSERT_TRUE(oob::write_u16(buf, 0x0002)); // 2 bytes: half a header

    EXPECT_FALSE(oob::probe_request_find(buf));
}

// A forward-compatible longer TLV value (extra trailing bytes) still parses.
TEST(OobProbe, ToleratesLongerTlvValue)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::tlv_write_header(buf, oob::tlv_probe_request, false,
                                      oob::ProbeRequest::wire_len + 4)); // 4 extra bytes
    ASSERT_TRUE(oob::write_u64(buf, 5));                                 // request_id
    ASSERT_TRUE(oob::write_u64(buf, 7));                                 // timestamp
    ASSERT_TRUE(oob::write_u32(buf, 0));                                 // flags
    ASSERT_TRUE(oob::write_u32(buf, 0xffffffff));                        // trailing bytes to skip

    const auto out_opt = oob::probe_request_find(buf);
    ASSERT_TRUE(out_opt);
    const auto &out = *out_opt; // NOLINT(bugprone-unchecked-optional-access) -- guarded by the ASSERT_TRUE above
    EXPECT_EQ(out.request_id, 5U);
    EXPECT_EQ(out.timestamp, 7U);
}

// A value shorter than the mandatory fields is invalid, however well-formed the
// TLV header is.
TEST(OobProbe, ShortTlvValueFails)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::tlv_write_header(buf, oob::tlv_probe_request, false, oob::ProbeRequest::wire_len - 1));
    for (std::size_t i = 0; i < oob::ProbeRequest::wire_len - 1; ++i)
    {
        buf.push_back(0);
    }

    EXPECT_FALSE(oob::probe_request_find(buf));
}

// Truncated input never crashes and fails cleanly (untrusted-network safety).
TEST(OobProbe, TruncatedInputFails)
{
    const oob::ProbeReply sent{.request_id = 0x9999999999999999ULL};
    BufferAllocated full(128);
    ASSERT_TRUE(sent.write(full));

    // every prefix shorter than the full message must fail, not throw
    for (size_t n = 0; n < full.size(); ++n)
    {
        BufferAllocated trunc(128);
        trunc.write(full.c_data(), n);
        EXPECT_FALSE(oob::probe_reply_find(trunc)) << "prefix len " << n;
    }
}

// A TLV whose declared length exceeds the buffer must fail, not over-read.
TEST(OobProbe, OversizedTlvLengthFails)
{
    BufferAllocated buf(128);
    // by hand: tlv_write_header() will not promise a value it has no room for
    ASSERT_TRUE(oob::write_u16(buf, oob::tlv_probe_request));
    ASSERT_TRUE(oob::write_u16(buf, 0xffff));
    ASSERT_TRUE(oob::write_u64(buf, 1)); // only a little body, far less than 0xffff

    EXPECT_FALSE(oob::probe_request_find(buf));
}

// With no message type ahead of the TLVs, the TLV type is what tells a request
// from a reply: reading one as the other finds a mandatory TLV it did not want.
TEST(OobProbe, RequestPayloadIsNotAReply)
{
    const oob::ProbeRequest sent{.timestamp = 1};
    BufferAllocated buf(128);
    ASSERT_TRUE(sent.write(buf));

    EXPECT_FALSE(oob::probe_reply_find(buf));
}
