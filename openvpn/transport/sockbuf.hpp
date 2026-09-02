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
 * @brief Portable socket send/receive buffer sizing for the datagram transports.
 *
 * @details
 * Wraps @c SockOpt's POSIX force-capable primitives (`openvpn/common/sockopt.hpp`)
 * behind an asio-socket-facing API that also works on Windows, and reports what
 * the kernel actually granted so a caller can log buffer provenance.
 *
 * Why this exists at all: a plain `SO_RCVBUF` request is silently clamped to the
 * host's `net.core.rmem_max` (208 KB on a stock host), which caps single-flow
 * throughput at `buffer / RTT` regardless of link capacity. The privileged
 * `SO_RCVBUFFORCE` variant bypasses that ceiling. Both transports need the same
 * fallback ladder and the same provenance reporting, so it lives in one place.
 */

#ifndef OPENVPN_TRANSPORT_SOCKBUF_H
#define OPENVPN_TRANSPORT_SOCKBUF_H

#include <sstream>
#include <string>

#include <openvpn/common/platform.hpp>
#include <openvpn/io/io.hpp>

#if !defined(OPENVPN_PLATFORM_WIN)
#include <openvpn/common/sockopt.hpp>
#endif

namespace openvpn::SockBuf {

/**
 * @brief What happened when one direction of a socket buffer was sized.
 * @details Deliberately a value type with no failure signalling: buffer sizing
 *  is advisory and must never fail a connection. Callers log it.
 */
struct Result
{
    /** Bytes asked for; 0 means the kernel default was left in place. */
    int requested = 0;

    /**
     * Bytes the kernel reports after the request, or 0 if unreadable.
     * @note On Linux this is normally ~2x @c requested when the request was
     *  honored, because the kernel doubles the value for its own bookkeeping.
     */
    int actual = 0;

    /** True if the privileged forcing variant succeeded, i.e. the request was
     *  allowed past the host ceiling. Always false on Windows. */
    bool forced = false;

    /** True if a request was made and the syscall succeeded. Does not imply the
     *  size was honored; see @c clamped(), which compares like with like. */
    bool ok = false;

    /**
     * @brief The size actually in effect, with the kernel's bookkeeping factor
     *  removed.
     * @details Linux reports twice the effective size through @c getsockopt, so
     *  @c actual is not comparable with @c requested directly. Every size
     *  comparison goes through here.
     * @return Bytes of buffer in effect, in the same units as @c requested.
     */
    [[nodiscard]] int effective() const
    {
#if defined(__linux__)
        return actual / 2;
#else
        return actual;
#endif
    }

    /** True if the kernel granted less than was asked for. */
    [[nodiscard]] bool clamped() const
    {
        return requested > 0 && actual > 0 && effective() < requested;
    }

    /**
     * @brief One-line provenance description, for logging.
     * @details Benchmarks comparing two data paths are meaningless if their
     *  buffers differ, so the effective size and how it was obtained belong in
     *  the log rather than in someone's reconstruction afterwards.
     * @return Human-readable summary, e.g.
     *  `"8388608 requested, 16777216 granted (forced)"`.
     */
    [[nodiscard]] std::string to_string() const
    {
        std::ostringstream os;
        if (!requested)
        {
            os << "kernel default " << actual;
            return os.str();
        }
        os << requested << " requested, ";
        if (!ok)
            os << "request failed, " << actual << " in effect";
        else
        {
            os << actual << " granted (";
            if (forced)
                os << "forced";
            else if (clamped())
                os << "clamped by host maximum";
            else
                os << "unforced";
            os << ')';
        }
        return os.str();
    }
};

/**
 * @brief Size an asio socket's receive buffer, forcing past the host ceiling
 *  where the platform and privileges allow.
 * @tparam SOCKET Any asio socket type exposing @c native_handle().
 * @param sock An open socket.
 * @param bytes Requested size; zero or negative leaves the kernel default,
 *  in which case the result still reports the inherited size.
 * @return What was requested, what was granted, and by which path.
 */
template <typename SOCKET>
inline Result set_rcvbuf(SOCKET &sock, const int bytes)
{
    Result res{.requested = bytes};
#if !defined(OPENVPN_PLATFORM_WIN)
    const SockOpt::BufSizeResult r = SockOpt::set_rcvbuf(sock.native_handle(), bytes);
    res.actual = r.actual;
    res.forced = r.forced;
    res.ok = r.ok;
#else
    // No forcing option on Windows; the plain request is all that is available.
    openvpn_io::error_code ec;
    if (bytes > 0)
    {
        sock.set_option(openvpn_io::socket_base::receive_buffer_size(bytes), ec);
        res.ok = !ec;
    }
    openvpn_io::socket_base::receive_buffer_size opt;
    sock.get_option(opt, ec);
    if (!ec)
        res.actual = opt.value();
#endif
    return res;
}

/**
 * @brief Size an asio socket's send buffer, forcing past the host ceiling where
 *  the platform and privileges allow.
 * @tparam SOCKET Any asio socket type exposing @c native_handle().
 * @param sock An open socket.
 * @param bytes Requested size; zero or negative leaves the kernel default.
 * @return What was requested, what was granted, and by which path.
 */
template <typename SOCKET>
inline Result set_sndbuf(SOCKET &sock, const int bytes)
{
    Result res{.requested = bytes};
#if !defined(OPENVPN_PLATFORM_WIN)
    const SockOpt::BufSizeResult r = SockOpt::set_sndbuf(sock.native_handle(), bytes);
    res.actual = r.actual;
    res.forced = r.forced;
    res.ok = r.ok;
#else
    openvpn_io::error_code ec;
    if (bytes > 0)
    {
        sock.set_option(openvpn_io::socket_base::send_buffer_size(bytes), ec);
        res.ok = !ec;
    }
    openvpn_io::socket_base::send_buffer_size opt;
    sock.get_option(opt, ec);
    if (!ec)
        res.actual = opt.value();
#endif
    return res;
}

} // namespace openvpn::SockBuf

#endif
