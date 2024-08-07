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

// Simple logging with data/time prepend

#pragma once

#include <iostream>
#include <openvpn/time/timestr.hpp>

#ifndef OPENVPN_LOG_STREAM
#define OPENVPN_LOG_STREAM std::cout
#endif

#define OPENVPN_LOG(args) OPENVPN_LOG_STREAM << date_time() << ' ' << args << std::endl

// like OPENVPN_LOG but no trailing newline
#define OPENVPN_LOG_NTNL(args) OPENVPN_LOG_STREAM << date_time() << ' ' << args

#define OPENVPN_LOG_STRING(str) OPENVPN_LOG_STREAM << date_time() << ' ' << (str)

// no-op constructs normally used with logthread.hpp
namespace openvpn::Log {
struct Context
{
    struct Wrapper
    {
    };
    Context(const Wrapper &)
    {
    }
};
} // namespace openvpn::Log
