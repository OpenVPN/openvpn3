//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2022 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <string>
#include <sstream>

#include <openvpn/common/arch.hpp>
#include <openvpn/common/version.hpp>
#include <openvpn/common/platform_name.hpp>

namespace openvpn {
inline std::string platform_string(const std::string &title, const std::string &app_version)
{
    std::ostringstream os;

    os << title << " ";
    if (!app_version.empty())
        os << app_version << '/';
    os << OPENVPN_VERSION;
#if defined OPENVPN_CORE_GIT_VERSION
    os << "(" << OPENVPN_CORE_GIT_VERSION << ")";
#endif
    os << ' ' << platform_name();
#if defined(OPENVPN_ARCH_x86_64)
    os << " x86_64";
#elif defined(OPENVPN_ARCH_i386)
    os << " i386";
#elif defined(OPENVPN_ARCH_ARM64)
    os << " arm64";
#elif defined(OPENVPN_ARCH_ARM)
#if defined(__ARM_ARCH_7S__) || defined(_ARM_ARCH_7S)
    os << " armv7s";
#elif defined(__ARM_ARCH_7A__)
    os << " armv7a";
#elif defined(__ARM_V7__) || defined(_ARM_ARCH_7)
    os << " armv7";
#else
    os << " arm";
#endif
#if defined(__thumb2__)
    os << " thumb2";
#elif defined(__thumb__) || defined(_M_ARMT)
    os << " thumb";
#endif
#endif // defined(OPENVPN_ARCH_ARM)

    os << ' ' << (sizeof(void *) * 8) << "-bit";
    return os.str();
}

inline std::string platform_string()
{
    return platform_string("OpenVPN core", "");
}
} // namespace openvpn
