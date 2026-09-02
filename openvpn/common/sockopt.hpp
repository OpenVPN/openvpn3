//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#ifndef OPENVPN_COMMON_SOCKOPT_H
#define OPENVPN_COMMON_SOCKOPT_H

#include <openvpn/common/platform.hpp>

#if !defined(OPENVPN_PLATFORM_WIN)

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <openvpn/common/exception.hpp>

namespace openvpn::SockOpt {

#ifdef SO_REUSEPORT
// set SO_REUSEPORT for inter-thread load balancing
inline void reuseport(const int fd)
{
    int on = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on)) < 0)
        throw Exception("error setting SO_REUSEPORT on socket");
}
#endif

// set SO_REUSEADDR for TCP
inline void reuseaddr(const int fd)
{
    int on = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) < 0)
        throw Exception("error setting SO_REUSEADDR on socket");
}

// set TCP_NODELAY for TCP
inline void tcp_nodelay(const int fd)
{
    int state = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&state, sizeof(state)) != 0)
        throw Exception("error setting TCP_NODELAY on socket");
}

// set FD_CLOEXEC to prevent fd from being passed across execs
inline void set_cloexec(const int fd)
{
    if (::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        throw Exception("error setting FD_CLOEXEC on file-descriptor/socket");
}

// set non-block mode on socket
static inline void set_nonblock(const int fd)
{
    if (::fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
        throw Exception("error setting socket to non-blocking mode");
}

/**
 * @brief Outcome of a socket send/receive buffer sizing request.
 * @details Reported rather than thrown because buffer sizing is advisory: a
 *  kernel that declines the request, or clamps it, must not fail a connection.
 *  Callers that care (a data path sizing for bandwidth-delay product, a
 *  benchmark that must not compare unequal buffers) log @c actual and
 *  @c forced instead of assuming the request was honored.
 */
struct BufSizeResult
{
    /** Bytes asked for. */
    int requested = 0;

    /**
     * Bytes the kernel reports via @c getsockopt after the request, or 0 if it
     * could not be read back.
     * @note On Linux this is normally ~2x @c requested: the kernel doubles the
     *  value to account for its own bookkeeping overhead. A caller that logs
     *  this without saying so will generate confused bug reports.
     */
    int actual = 0;

    /** True if the privileged @c SO_*BUFFORCE variant succeeded, i.e. the
     *  request was allowed past the @c net.core.{r,w}mem_max ceiling. */
    bool forced = false;

    /**
     * True if either variant succeeded. False when no size was requested, in
     * which case @c actual still reports the inherited kernel default.
     * @warning @c ok means the @c setsockopt call returned success, not that
     *  the request was honored: the plain variant succeeds while silently
     *  clamping to the host ceiling. Compare @c actual against @c requested.
     */
    bool ok = false;
};

namespace detail {

/** Sentinel for @c set_sock_buf's @p opt_force meaning "no forcing option on
 *  this platform". No @c SOL_SOCKET option number is negative. */
inline constexpr int NO_FORCE_OPT = -1;

/**
 * @brief Size one direction of a socket buffer, preferring the privileged
 *  forcing variant, and read back what the kernel actually granted.
 * @details Tries @p opt_force first (which on Linux bypasses the
 *  @c net.core.{r,w}mem_max ceiling but requires @c CAP_NET_ADMIN), then falls
 *  back to plain @p opt, whose value is silently clamped to that ceiling. This
 *  ordering matters: a plain request is capped at @c rmem_max (208 KB on a
 *  stock host), which is far below the bandwidth-delay product a single flow
 *  needs at WAN latency.
 * @param fd Socket descriptor. A negative value is a no-op.
 * @param bytes Requested size. Zero or negative is a no-op, meaning "leave the
 *  kernel default alone".
 * @param opt The plain option (@c SO_RCVBUF or @c SO_SNDBUF).
 * @param opt_force The forcing option, or @c NO_FORCE_OPT if unavailable.
 * @return What was requested, what was granted, and by which path.
 */
inline BufSizeResult set_sock_buf(const int fd,
                                  const int bytes,
                                  const int opt,
                                  const int opt_force) noexcept
{
    BufSizeResult res{.requested = bytes};
    if (fd < 0)
        return res;

    if (bytes > 0)
    {
        if (opt_force != NO_FORCE_OPT
            && ::setsockopt(fd, SOL_SOCKET, opt_force, &bytes, sizeof(bytes)) == 0)
        {
            res.ok = true;
            res.forced = true;
        }
        else if (::setsockopt(fd, SOL_SOCKET, opt, &bytes, sizeof(bytes)) == 0)
        {
            res.ok = true;
        }
    }

    // Read back even when nothing was requested and even when the request
    // failed: a caller logging buffer provenance needs the size actually in
    // effect, which for the no-op case is the kernel default it inherited.
    int granted = 0;
    socklen_t len = sizeof(granted);
    if (::getsockopt(fd, SOL_SOCKET, opt, &granted, &len) == 0)
        res.actual = granted;

    return res;
}

} // namespace detail

/**
 * @brief Size a socket's receive buffer, forcing past the host ceiling if
 *  permitted.
 * @details Uses @c SO_RCVBUFFORCE where available (Linux, @c CAP_NET_ADMIN),
 *  falling back to @c SO_RCVBUF. Never throws; see @c BufSizeResult for why.
 * @param fd Socket descriptor.
 * @param bytes Requested size; zero or negative leaves the kernel default.
 * @return The outcome, including the @c getsockopt-confirmed size.
 */
inline BufSizeResult set_rcvbuf(const int fd, const int bytes) noexcept
{
#ifdef SO_RCVBUFFORCE
    return detail::set_sock_buf(fd, bytes, SO_RCVBUF, SO_RCVBUFFORCE);
#else
    return detail::set_sock_buf(fd, bytes, SO_RCVBUF, detail::NO_FORCE_OPT);
#endif
}

/**
 * @brief Size a socket's send buffer, forcing past the host ceiling if
 *  permitted.
 * @details Uses @c SO_SNDBUFFORCE where available (Linux, @c CAP_NET_ADMIN),
 *  falling back to @c SO_SNDBUF. Never throws; see @c BufSizeResult for why.
 * @param fd Socket descriptor.
 * @param bytes Requested size; zero or negative leaves the kernel default.
 * @return The outcome, including the @c getsockopt-confirmed size.
 */
inline BufSizeResult set_sndbuf(const int fd, const int bytes) noexcept
{
#ifdef SO_SNDBUFFORCE
    return detail::set_sock_buf(fd, bytes, SO_SNDBUF, SO_SNDBUFFORCE);
#else
    return detail::set_sock_buf(fd, bytes, SO_SNDBUF, detail::NO_FORCE_OPT);
#endif
}

} // namespace openvpn::SockOpt

#endif
#endif
