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

#include <openvpn/ssl/oob_probe.hpp>

using namespace openvpn;

namespace {

// Build a deterministic ProtoSessionID from 8 known bytes.
ProtoSessionID make_psid(const unsigned char (&bytes)[ProtoSessionID::SIZE])
{
    BufferAllocated b(ProtoSessionID::SIZE);
    b.write(bytes, ProtoSessionID::SIZE);
    return ProtoSessionID(b);
}

} // namespace

// SERVER_PROBE round-trips: what we write, we read back identically.
TEST(oob_probe, server_probe_roundtrip)
{
    const oob::ProbeParameter in{.timestamp = 0x1122334455667788ULL, .flags = 0};

    BufferAllocated buf(128);
    ASSERT_TRUE(oob::server_probe_write(buf, in));

    const auto out = oob::server_probe_read(buf);
    ASSERT_TRUE(out);
    EXPECT_EQ(out->timestamp, in.timestamp);
    EXPECT_EQ(out->flags, in.flags);
}

// PROBE_REPLY round-trips, session id and all fields preserved.
TEST(oob_probe, probe_reply_roundtrip)
{
    const unsigned char sid[ProtoSessionID::SIZE] = {1, 2, 3, 4, 5, 6, 7, 8};
    const oob::ProbeReply in{.peer_session_id = make_psid(sid),
                             .priority = 100,
                             .weight = 50,
                             .max_latency_diff = 25,
                             .connect_lifetime = 60,
                             .flags = oob::REPLY_FLAG_RESEND_WKC};

    BufferAllocated buf(128);
    ASSERT_TRUE(oob::client_reply_write(buf, in));

    const auto out = oob::client_reply_read(buf);
    ASSERT_TRUE(out);
    EXPECT_TRUE(out->peer_session_id.match(in.peer_session_id));
    EXPECT_EQ(out->priority, in.priority);
    EXPECT_EQ(out->weight, in.weight);
    EXPECT_EQ(out->connect_lifetime, in.connect_lifetime);
    EXPECT_EQ(out->flags, in.flags);
    EXPECT_EQ(out->max_latency_diff, in.max_latency_diff);
}

// Wire format is locked (big-endian) so it stays interoperable with the C impl.
TEST(oob_probe, server_probe_wire_format)
{
    const oob::ProbeParameter in{.timestamp = 0x1122334455667788ULL, .flags = 0};

    BufferAllocated buf(128);
    ASSERT_TRUE(oob::server_probe_write(buf, in));

    const unsigned char expected[] = {
        0x01,
        0x00, // msg type SERVER_PROBE (0x100)
        0x02,
        0x00, // TLV type 0x200 (not optional)
        0x00,
        0x0c, // TLV value length = 12
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
        0x00, // flags (BE)
    };
    ASSERT_EQ(buf.size(), sizeof(expected));
    EXPECT_EQ(std::memcmp(buf.c_data(), expected, sizeof(expected)), 0);
}

// PROBE_REPLY wire format is locked to the spec's field order
// (priority, weight, max_latency_diff, connect_lifetime, flags).
TEST(oob_probe, probe_reply_wire_format)
{
    const unsigned char sid[ProtoSessionID::SIZE] = {1, 2, 3, 4, 5, 6, 7, 8};
    const oob::ProbeReply in{.peer_session_id = make_psid(sid),
                             .priority = 100,
                             .weight = 50,
                             .max_latency_diff = 25,
                             .connect_lifetime = 60,
                             .flags = oob::REPLY_FLAG_RESEND_WKC};

    BufferAllocated buf(128);
    ASSERT_TRUE(oob::client_reply_write(buf, in));

    const unsigned char expected[] = {
        0x01,
        0x01, // msg type PROBE_REPLY (0x101)
        0x02,
        0x01, // TLV type 0x201 (not optional)
        0x00,
        0x14, // TLV value length = 20
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08, // peer_session_id
        0x00,
        0x64, // priority = 100 (BE)
        0x00,
        0x32, // weight = 50 (BE)
        0x00,
        0x19, // max_latency_diff = 25 (BE)
        0x00,
        0x3c, // connect_lifetime = 60 (BE)
        0x00,
        0x00,
        0x00,
        0x01, // flags = REPLY_FLAG_RESEND_WKC (BE)
    };
    ASSERT_EQ(buf.size(), sizeof(expected));
    EXPECT_EQ(std::memcmp(buf.c_data(), expected, sizeof(expected)), 0);
}

// Unknown *optional* TLVs before the wanted one are skipped (forward compatibility).
TEST(oob_probe, skips_unknown_optional_tlv)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::msg_write_header(buf, oob::MSG_SERVER_PROBE));
    // an unknown TLV (type 0x7ff, 3 bytes of value) marked optional, so skippable
    ASSERT_TRUE(oob::tlv_write_header(buf, 0x7ff, true, 3));
    ASSERT_TRUE(oob::write_u16(buf, 0xdead));
    buf.push_back(0xaa);
    // the real probe_parameter TLV
    const oob::ProbeParameter in{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(in.write(buf));

    const auto out = oob::server_probe_read(buf);
    ASSERT_TRUE(out);
    EXPECT_EQ(out->timestamp, 42u);
}

// The same message is rejected when that TLV is not marked optional: we cannot
// act on a message carrying something mandatory we do not understand.
TEST(oob_probe, rejects_unknown_mandatory_tlv)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::msg_write_header(buf, oob::MSG_SERVER_PROBE));
    ASSERT_TRUE(oob::tlv_write_header(buf, 0x7ff, false, 3));
    ASSERT_TRUE(oob::write_u16(buf, 0xdead));
    buf.push_back(0xaa);
    const oob::ProbeParameter in{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(in.write(buf));

    EXPECT_FALSE(oob::server_probe_read(buf));
}

// ... and equally when that TLV sits *after* the one we were looking for.
TEST(oob_probe, rejects_unknown_mandatory_tlv_after_wanted)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::msg_write_header(buf, oob::MSG_SERVER_PROBE));
    const oob::ProbeParameter in{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(in.write(buf));
    ASSERT_TRUE(oob::tlv_write_header(buf, 0x7ff, false, 3));
    ASSERT_TRUE(oob::write_u16(buf, 0xdead));
    buf.push_back(0xaa);

    EXPECT_FALSE(oob::server_probe_read(buf));
}

// An unknown *optional* TLV after the wanted one is skipped, not tripped over.
TEST(oob_probe, skips_unknown_optional_tlv_after_wanted)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::msg_write_header(buf, oob::MSG_SERVER_PROBE));
    const oob::ProbeParameter in{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(in.write(buf));
    ASSERT_TRUE(oob::tlv_write_header(buf, 0x7ff, true, 3));
    ASSERT_TRUE(oob::write_u16(buf, 0xdead));
    buf.push_back(0xaa);

    const auto out = oob::server_probe_read(buf);
    ASSERT_TRUE(out);
    EXPECT_EQ(out->timestamp, 42u);
}

// The probe TLV may appear only once; a second one is not something to choose
// between.
TEST(oob_probe, rejects_repeated_probe_tlv)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::msg_write_header(buf, oob::MSG_SERVER_PROBE));
    ASSERT_TRUE((oob::ProbeParameter{.timestamp = 42, .flags = 0}).write(buf));
    ASSERT_TRUE((oob::ProbeParameter{.timestamp = 43, .flags = 0}).write(buf));

    EXPECT_FALSE(oob::server_probe_read(buf));
}

// Trailing bytes too few to hold a TLV header are a truncated entry, not padding.
TEST(oob_probe, rejects_trailing_partial_header)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::msg_write_header(buf, oob::MSG_SERVER_PROBE));
    const oob::ProbeParameter in{.timestamp = 42, .flags = 0};
    ASSERT_TRUE(in.write(buf));
    ASSERT_TRUE(oob::write_u16(buf, 0x0002)); // 2 bytes: half a header

    EXPECT_FALSE(oob::server_probe_read(buf));
}

// A forward-compatible longer TLV value (extra trailing bytes) still parses.
TEST(oob_probe, tolerates_longer_tlv_value)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::msg_write_header(buf, oob::MSG_SERVER_PROBE));
    ASSERT_TRUE(oob::tlv_write_header(buf, oob::TLV_PROBE_PARAMETER, false,
                                      oob::ProbeParameter::WIRE_LEN + 4)); // 4 extra bytes
    ASSERT_TRUE(oob::write_u64(buf, 7));
    ASSERT_TRUE(oob::write_u32(buf, 0));
    ASSERT_TRUE(oob::write_u32(buf, 0xffffffff)); // trailing bytes to skip

    const auto out = oob::server_probe_read(buf);
    ASSERT_TRUE(out);
    EXPECT_EQ(out->timestamp, 7u);
}

// Truncated input never crashes and fails cleanly (untrusted-network safety).
TEST(oob_probe, truncated_input_fails)
{
    const unsigned char sid[ProtoSessionID::SIZE] = {9, 9, 9, 9, 9, 9, 9, 9};
    const oob::ProbeReply in{.peer_session_id = make_psid(sid)};
    BufferAllocated full(128);
    ASSERT_TRUE(oob::client_reply_write(full, in));

    // every prefix shorter than the full message must fail, not throw
    for (size_t n = 0; n < full.size(); ++n)
    {
        BufferAllocated trunc(128);
        trunc.write(full.c_data(), n);
        EXPECT_FALSE(oob::client_reply_read(trunc)) << "prefix len " << n;
    }
}

// A TLV whose declared length exceeds the buffer must fail, not over-read.
TEST(oob_probe, oversized_tlv_length_fails)
{
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::msg_write_header(buf, oob::MSG_SERVER_PROBE));
    ASSERT_TRUE(oob::tlv_write_header(buf, oob::TLV_PROBE_PARAMETER, false, 0xffff));
    ASSERT_TRUE(oob::write_u64(buf, 1)); // only a little body, far less than 0xffff

    EXPECT_FALSE(oob::server_probe_read(buf));
}

// Wrong message type is rejected.
TEST(oob_probe, wrong_message_type_fails)
{
    const oob::ProbeParameter in{.timestamp = 1};
    BufferAllocated buf(128);
    ASSERT_TRUE(oob::server_probe_write(buf, in)); // this is a SERVER_PROBE

    EXPECT_FALSE(oob::client_reply_read(buf)); // read as PROBE_REPLY -> fail
}
