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
 * @brief Capability probe shared by the Linux-only privileged unit tests.
 *
 * @details
 * Several suites here self-skip rather than fail when run unprivileged, and each
 * had grown its own copy of the same CAP_NET_ADMIN check. Kept out of
 * `test_common.hpp` deliberately: that header is included on every platform,
 * and `<sys/capability.h>` exists only on Linux.
 */

#pragma once

#include <sys/capability.h>

namespace openvpn::test {

/**
 * @brief Report whether the calling process holds CAP_NET_ADMIN.
 * @return True when the capability is effective, so a privileged test may run.
 */
inline bool have_cap_net_admin()
{
    cap_t cap = cap_get_proc();
    cap_flag_value_t v = CAP_CLEAR;
    cap_get_flag(cap, CAP_NET_ADMIN, CAP_EFFECTIVE, &v);
    cap_free(cap);
    return v == CAP_SET;
}

} // namespace openvpn::test
