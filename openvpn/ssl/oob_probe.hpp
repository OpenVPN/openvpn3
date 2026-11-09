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
 * Encoding/decoding of out-of-band (CONTROL_V2) control messages, used for
 * server latency probing and best-server selection.
 *
 * An OOB message payload starts with a 16-bit message type (the 0x1xx space:
 * SERVER_PROBE, PROBE_REPLY, ...) followed by a sequence of TLV entries. Each TLV
 * starts with a 4-byte header: a 16-bit field whose most significant bit is the
 * "optional" flag and whose remaining 15 bits are the type (the 0x2xx space),
 * followed by a 16-bit length. Unknown/trailing bytes are ignored on read, so the
 * format is forward-compatible.
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

//! OOB message types: the 16-bit value at the start of an OOB payload.
enum : std::uint16_t
{
    MSG_SERVER_PROBE = 0x100,
    MSG_PROBE_REPLY = 0x101,
};

//! TLV header bit layout of the first 16-bit field, and the TLV type space (0x2xx).
enum : std::uint16_t
{
    TLV_OPTIONAL_FLAG = 0x8000,
    TLV_TYPE_MASK = 0x7fff,
    TLV_PROBE_PARAMETER = 0x200,
    TLV_PROBE_REPLY = 0x201,
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

// ---- message + TLV headers ----------------------------------------------------

//! Write an OOB message-type header (the 16-bit type preceding the TLVs).
inline bool msg_write_header(Buffer &buf, std::uint16_t msg_type)
{
    return write_u16(buf, msg_type);
}

/**
 * Read and verify an OOB message-type header, advancing past it.
 * @param buf                buffer positioned at the OOB message payload
 * @param expected_msg_type  the message type the payload must carry
 * @return true if a message type was read and equals @p expected_msg_type
 */
inline bool msg_read_header(Buffer &buf, std::uint16_t expected_msg_type)
{
    std::uint16_t msg_type;
    return read_u16(buf, msg_type) && msg_type == expected_msg_type;
}

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

// ---- probe_parameter / probe_reply TLVs -----------------------------------------

//! probe parameter TLV (sent by the client in a SERVER_PROBE).
struct ProbeParameter
{
    //! minimum on-wire value length (u64 timestamp + u32 flags, excluding the
    //! 4-byte TLV header); may be longer on the wire for forward compatibility
    static constexpr std::size_t WIRE_LEN = 12;

    std::uint64_t timestamp = 0; //!< client clock as a UNIX timestamp
    std::uint32_t flags = 0;     //!< client capability flags, currently must be 0

    //! Append this parameter as a complete TLV (header + value) to @p buf.
    bool write(Buffer &buf) const
    {
        return tlv_write_header(buf, TLV_PROBE_PARAMETER, false, WIRE_LEN)
               && write_u64(buf, timestamp)
               && write_u32(buf, flags);
    }

    /**
     * Read a probe_parameter TLV value of @p value_len bytes from @p buf. The TLV
     * header must already have been consumed. @p value_len bytes are consumed on
     * success, including any trailing bytes beyond the fields understood here.
     */
    static std::optional<ProbeParameter> read(Buffer &buf, std::uint16_t value_len)
    {
        if (value_len < WIRE_LEN)
            return std::nullopt;
        ProbeParameter p;
        if (!read_u64(buf, p.timestamp) || !read_u32(buf, p.flags))
            return std::nullopt;
        if (!skip_trailing(buf, value_len, WIRE_LEN))
            return std::nullopt;
        return p;
    }
};

//! probe reply TLV (sent by the server in a PROBE_REPLY).
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

    //! Read a probe_reply TLV value of @p value_len bytes; see ProbeParameter::read().
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

// ---- full SERVER_PROBE / PROBE_REPLY messages ---------------------------------

//! Write a complete SERVER_PROBE (message header + probe_parameter TLV). Client.
inline bool server_probe_write(Buffer &buf, const ProbeParameter &param)
{
    return msg_write_header(buf, MSG_SERVER_PROBE) && param.write(buf);
}

/**
 * Read a received SERVER_PROBE: verify the message header, then scan for the
 * probe_parameter TLV (tolerating other/future TLVs). Consumes @p buf as it reads.
 * @return the parameter if the header matched and a well-formed probe_parameter
 *         was found, std::nullopt otherwise
 */
inline std::optional<ProbeParameter> server_probe_read(Buffer &buf)
{
    if (!msg_read_header(buf, MSG_SERVER_PROBE))
        return std::nullopt;
    const auto value_len = find_tlv(buf, TLV_PROBE_PARAMETER);
    if (!value_len)
        return std::nullopt;
    return ProbeParameter::read(buf, *value_len);
}

//! Write a complete PROBE_REPLY (message header + probe_reply TLV). Server.
inline bool client_reply_write(Buffer &buf, const ProbeReply &reply)
{
    return msg_write_header(buf, MSG_PROBE_REPLY) && reply.write(buf);
}

/**
 * Read a received PROBE_REPLY: the client-side counterpart of server_probe_read().
 * @return the reply if the header matched and a well-formed probe_reply was
 *         found, std::nullopt otherwise
 */
inline std::optional<ProbeReply> client_reply_read(Buffer &buf)
{
    if (!msg_read_header(buf, MSG_PROBE_REPLY))
        return std::nullopt;
    const auto value_len = find_tlv(buf, TLV_PROBE_REPLY);
    if (!value_len)
        return std::nullopt;
    return ProbeReply::read(buf, *value_len);
}

} // namespace openvpn::oob

#endif
