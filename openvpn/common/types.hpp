//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

// define very basic types such as NULL, size_t, ssize_t, and count_t

#ifndef OPENVPN_COMMON_TYPES_H
#define OPENVPN_COMMON_TYPES_H

#include <cstddef> // defines size_t and NULL

#include <openvpn/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_WIN
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <unistd.h> // get ssize_t
#endif

namespace openvpn {

  typedef long long count_t;

} // namespace openvpn

#endif // OPENVPN_COMMON_TYPES_H
