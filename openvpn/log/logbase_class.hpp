//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2024 OpenVPN Inc.
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

#include <openvpn/common/rc.hpp>

#define OPENVPN_LOG_CLASS openvpn::LogBase

namespace openvpn {

/**
 * @brief The logging interface, simple, logs a string
 */
struct LogBase : RC<thread_safe_refcount>
{
    // As demonstrated here by the comment out of Ptr, objects of type LogBase are
    // never used in the intrusive pointer mode.  However, removing the base class
    // exposes other types derived from LogBase (e.g., RunContextBase) which are reliant
    // upon the RC base class here.  FIXME!

    // typedef RCPtr<LogBase> Ptr;

    virtual void log(const std::string &str) = 0;
};

} // namespace openvpn
