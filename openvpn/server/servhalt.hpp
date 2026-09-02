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

#pragma once

#include <string>

namespace openvpn::HaltRestart {
enum Type
{
    HALT,            // disconnect
    RESTART,         // restart, don't preserve session token
    RESTART_PSID,    // restart, preserve session token
    RESTART_PASSIVE, // restart, preserve session token and local client instance object
    AUTH_FAILED,     // auth fail, don't preserve session token
    RAW,             // pass raw message to client
};

inline std::string to_string(Type type)
{
    switch (type)
    {
    case HALT:
        return "HALT";
    case RESTART:
        return "RESTART";
    case RESTART_PSID:
        return "RESTART_PSID";
    case RESTART_PASSIVE:
        return "RESTART_PASSIVE";
    case AUTH_FAILED:
        return "AUTH_FAILED";
    case RAW:
        return "RAW";
    default:
        return "HaltRestart_?";
    }
}
} // namespace openvpn::HaltRestart

namespace openvpn {
/**
 * @brief Why a server-side session is being torn down.
 * @details Recorded by the protocol session as the cause becomes known and
 *  handed to the management layer immediately before teardown, so an
 *  embedder's disconnect callback can distinguish an orderly client exit from
 *  a keepalive timeout from a server shutdown. @c UNKNOWN covers the paths
 *  that carry no distinguishing signal: transport errors, protocol errors,
 *  and session invalidation other than keepalive.
 */
enum class DisconnectCause
{
    UNKNOWN,
    KEEPALIVE_TIMEOUT,
    CLIENT_EXIT,
    SERVER_SHUTDOWN,
};

/**
 * @brief Render a cause for logging.
 * @param type The cause to render.
 * @return A stable, human-readable name.
 */
inline std::string to_string(const DisconnectCause type)
{
    using enum DisconnectCause;

    switch (type)
    {
    case UNKNOWN:
        return "UNKNOWN";
    case KEEPALIVE_TIMEOUT:
        return "KEEPALIVE_TIMEOUT";
    case CLIENT_EXIT:
        return "CLIENT_EXIT";
    case SERVER_SHUTDOWN:
        return "SERVER_SHUTDOWN";
    default:
        return "DisconnectCause_?";
    }
}
} // namespace openvpn
