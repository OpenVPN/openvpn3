//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Inc.
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

#include <cstdint>

#include <openvpn/common/endian_platform.hpp>

namespace openvpn {
  namespace Endian {
    inline std::uint64_t rev64(const std::uint64_t value)
    {
#ifdef OPENVPN_LITTLE_ENDIAN
#ifdef __clang__
      return __builtin_bswap64(value);
#elif _MSC_VER
      return _byteswap_uint64(value);
#else
      return __bswap_constant_64(value);
#endif /* _MSC_VER */
#else
      return value;
#endif /* OPENVPN_LITTLE_ENDIAN */
    }
  }
}
