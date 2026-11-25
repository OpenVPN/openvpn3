//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Technologies, Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception

#pragma once

#include <string>

#include <openvpn/common/to_string.hpp>

namespace openvpn {

template <class EPRANGE>
inline std::string asio_resolver_results_to_string(const EPRANGE &endpoint_range)
{
    std::string ret;
    ret.reserve(64);
    bool first = true;
    for (const auto &i : endpoint_range)
    {
        if (!first)
            ret += ' ';
        ret += '[';
        ret += openvpn::to_string(i.endpoint().address());
        ret += "]:";
        ret += openvpn::to_string(i.endpoint().port());
        first = false;
    }
    return ret;
}

} // namespace openvpn
