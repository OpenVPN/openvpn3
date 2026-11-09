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
 * Encoding and decoding of the server probe TLVs, carried in a CONTROL_V2
 * control message and used for latency probing and best-server selection.
 *
 * A CONTROL_V2 payload is a bare sequence of TLVs, with no message type ahead of
 * them. Each TLV starts with a 4-byte header: a 16-bit field whose most
 * significant bit is the "optional" flag and whose remaining 15 bits are the
 * type, followed by a 16-bit length of the value. The type space is shared with
 * the other TLV-carrying control messages.
 *
 * All multi-byte integers are big-endian (network byte order), matching the
 * community C implementation (buf_write_u16 = htons, etc.) for on-the-wire
 * interop. Read paths parse unsolicited datagrams from the network, where
 * malformed input is the expected case rather than the exception, so they are
 * bounds-checked and return std::nullopt / false instead of throwing.
 */

#ifndef OPENVPN_SSL_OOB_PROBE_H
#define OPENVPN_SSL_OOB_PROBE_H

#include <cstdint>
#include <cstring>
#include <optional>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/buffer/bufbe.hpp>
#include <openvpn/ssl/psid.hpp>

namespace openvpn::oob {

// big-endian integer read/write on a Buffer (shared helpers)
using BufferBE::read_u16;
using BufferBE::read_u32;
using BufferBE::read_u64;
using BufferBE::write_u16;
using BufferBE::write_u32;
using BufferBE::write_u64;

//! TLV header bit layout of the first 16-bit field, and the probe TLV types. The
//! shared type space puts 0x1 on the early negotiation flags of
//! CONTROL_HARD_RESET_SERVER_V2.
enum : std::uint16_t
{
    TLV_OPTIONAL_FLAG = 0x8000,
    TLV_TYPE_MASK = 0x7fff,
    TLV_PROBE_REQUEST = 0x2,
    TLV_PROBE_REPLY = 0x3,
};

/**
 * probe_reply flags (the reply TLV's 32-bit flags field).
 *
 * bit 0 (RESEND_WKC): the client must resend the wrapped client key (via
 * CONTROL_WKC_V1) when it completes the handshake using this reply as a shortcut.
 * Set by a tls-crypt-v2 server, which is stateless and discarded the WKc.
 */
enum : std::uint32_t
{
    REPLY_FLAG_RESEND_WKC = 0x1,
};

// ---- TLV header ---------------------------------------------------------------

//! A decoded TLV header.
struct TlvHeader
{
    std::uint16_t type;      //!< the 15-bit TLV type
    bool optional;           //!< the optional flag
    std::uint16_t value_len; //!< the declared value length
};

//! Write a TLV header (type + optional flag + value length) to @p buf.
inline bool tlv_write_header(Buffer &buf, std::uint16_t type, bool optional, std::uint16_t value_len)
{
    std::uint16_t field = type & TLV_TYPE_MASK;
    if (optional)
        field |= TLV_OPTIONAL_FLAG;
    return write_u16(buf, field) && write_u16(buf, value_len);
}

/**
 * Read a TLV header from @p buf, advancing past it.
 * @return the decoded header, or std::nullopt if there are not enough bytes
 */
inline std::optional<TlvHeader> tlv_read_header(Buffer &buf)
{
    std::uint16_t field, value_len;
    if (!read_u16(buf, field) || !read_u16(buf, value_len))
        return std::nullopt;
    return TlvHeader{.type = static_cast<std::uint16_t>(field & TLV_TYPE_MASK),
                     .optional = (field & TLV_OPTIONAL_FLAG) != 0,
                     .value_len = value_len};
}

/**
 * Consume a TLV value of @p value_len bytes, of which @p consumed have already
 * been read, skipping any trailing bytes this version does not understand.
 * @return false if fewer than @p consumed bytes were declared, or the buffer is
 *         too short for the remainder
 */
inline bool skip_trailing(Buffer &buf, std::uint16_t value_len, std::size_t consumed)
{
    if (value_len < consumed)
        return false;
    const std::size_t rest = value_len - consumed;
    if (buf.size() < rest)
        return false;
    buf.advance(rest);
    return true;
}

/**
 * Scan @p buf for the TLV of type @p wanted_type, skipping any other type that is
 * marked optional. On success @p buf is left at that TLV's value and its declared
 * length is returned.
 *
 * The whole sequence is walked even once the wanted TLV has been found, because
 * a mandatory TLV we do not understand invalidates the message wherever it sits,
 * as does a second TLV of @p wanted_type. The scan runs on a copy of the buffer
 * view, so a message we refuse never leaves @p buf inside a value.
 */
inline std::optional<std::uint16_t> find_tlv(Buffer &buf, std::uint16_t wanted_type)
{
    Buffer scan(buf); // walk the sequence without moving buf off the match
    std::optional<std::uint16_t> found_len;
    std::size_t found_offset = 0;

    while (!scan.empty())
    {
        const auto hdr = tlv_read_header(scan);
        if (!hdr)
        {
            return std::nullopt; // fewer bytes left than a TLV header
        }
        if (hdr->type == wanted_type)
        {
            if (found_len)
            {
                return std::nullopt; // the TLV may occur only once
            }
            found_len = hdr->value_len;
            found_offset = buf.size() - scan.size(); // start of its value
        }
        else if (!hdr->optional)
        {
            return std::nullopt;
        }
        if (scan.size() < hdr->value_len)
        {
            return std::nullopt; // the header claims more than is there
        }
        scan.advance(hdr->value_len);
    }

    if (found_len)
    {
        buf.advance(found_offset);
    }
    return found_len;
}

// ---- probe request / probe reply TLVs -----------------------------------------

//! probe request TLV, sent by a client to probe a server.
struct ProbeRequest
{
    //! minimum on-wire value length (u64 timestamp + u32 flags, excluding the
    //! 4-byte TLV header); may be longer on the wire for forward compatibility
    static constexpr std::size_t WIRE_LEN = 12;

    std::uint64_t timestamp = 0; //!< client clock as a UNIX timestamp
    std::uint32_t flags = 0;     //!< client capability flags, currently must be 0

    //! Append this request as a complete TLV (header + value) to @p buf.
    bool write(Buffer &buf) const
    {
        return tlv_write_header(buf, TLV_PROBE_REQUEST, false, WIRE_LEN)
               && write_u64(buf, timestamp)
               && write_u32(buf, flags);
    }

    /**
     * Read a probe request TLV value of @p value_len bytes from @p buf. The TLV
     * header must already have been consumed. @p value_len bytes are consumed on
     * success, including any trailing bytes beyond the fields understood here.
     */
    static std::optional<ProbeRequest> read(Buffer &buf, std::uint16_t value_len)
    {
        if (value_len < WIRE_LEN)
            return std::nullopt;
        ProbeRequest r;
        if (!read_u64(buf, r.timestamp) || !read_u32(buf, r.flags))
            return std::nullopt;
        if (!skip_trailing(buf, value_len, WIRE_LEN))
            return std::nullopt;
        return r;
    }
};

//! probe reply TLV, a server's answer to a probe request.
struct ProbeReply
{
    //! minimum on-wire value length (psid(8) + u16*4 + u32, excluding the
    //! 4-byte TLV header); may be longer on the wire for forward compatibility
    static constexpr std::size_t WIRE_LEN = 20;

    ProtoSessionID peer_session_id;     //!< echoes the session id of the request
    std::uint16_t priority = 0;         //!< DNS-SRV style priority (lower preferred)
    std::uint16_t weight = 0;           //!< DNS-SRV style weight
    std::uint16_t max_latency_diff = 0; //!< candidate-band margin (ms); 0 = client default
    std::uint16_t connect_lifetime = 0; //!< seconds the reply is valid as a handshake shortcut
    std::uint32_t flags = 0;            //!< server behaviour flags (REPLY_FLAG_*)

    //! Append this reply as a complete TLV (header + value) to @p buf.
    bool write(Buffer &buf) const
    {
        if (!tlv_write_header(buf, TLV_PROBE_REPLY, false, WIRE_LEN))
            return false;
        if (buf.remaining() < ProtoSessionID::SIZE)
            return false;
        peer_session_id.write(buf);
        return write_u16(buf, priority)
               && write_u16(buf, weight)
               && write_u16(buf, max_latency_diff)
               && write_u16(buf, connect_lifetime)
               && write_u32(buf, flags);
    }

    //! Read a probe reply TLV value of @p value_len bytes; see ProbeRequest::read().
    static std::optional<ProbeReply> read(Buffer &buf, std::uint16_t value_len)
    {
        if (value_len < WIRE_LEN)
            return std::nullopt;
        if (buf.size() < ProtoSessionID::SIZE)
            return std::nullopt;
        ProbeReply r;
        r.peer_session_id.read(buf);
        if (!read_u16(buf, r.priority) || !read_u16(buf, r.weight) || !read_u16(buf, r.max_latency_diff)
            || !read_u16(buf, r.connect_lifetime) || !read_u32(buf, r.flags))
            return std::nullopt;
        if (!skip_trailing(buf, value_len, WIRE_LEN))
            return std::nullopt;
        return r;
    }
};

// ---- finding a probe TLV in a received payload --------------------------------

//! Find and parse the probe request TLV of a received CONTROL_V2 payload, which
//! find_tlv() requires to hold exactly one. Server side; consumes @p buf.
inline std::optional<ProbeRequest> probe_request_find(Buffer &buf)
{
    const auto value_len = find_tlv(buf, TLV_PROBE_REQUEST);
    if (!value_len)
        return std::nullopt;
    return ProbeRequest::read(buf, *value_len);
}

//! The client-side counterpart of probe_request_find().
inline std::optional<ProbeReply> probe_reply_find(Buffer &buf)
{
    const auto value_len = find_tlv(buf, TLV_PROBE_REPLY);
    if (!value_len)
        return std::nullopt;
    return ProbeReply::read(buf, *value_len);
}

} // namespace openvpn::oob

#endif
