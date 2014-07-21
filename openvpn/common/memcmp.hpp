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

#ifndef OPENVPN_COMMON_MEMCMP_H
#define OPENVPN_COMMON_MEMCMP_H

#include <cstddef> // defines size_t and NULL

// Constant-time memory comparison method.  Can be used in
// security-sensitive contexts to inhibit timing attacks.

namespace openvpn {

  // Is value of type T aligned on A boundary?
  // NOTE: requires that sizeof(A) is a power of 2
  template <typename T, typename A>
  inline bool is_aligned(const T value)
  {
    return (size_t(value) & (sizeof(A)-1)) == 0;
  }

  inline bool memcmp_secure(const unsigned char *p1, const unsigned char *p2, size_t size)
  {
    typedef unsigned int altword;
    if (is_aligned<const unsigned char *, altword>(p1) && is_aligned<const unsigned char *, altword>(p2) && is_aligned<size_t, altword>(size))
      {
	//OPENVPN_LOG("*** MEMCMP FAST");
	volatile altword *u1 = (volatile altword *)p1;
	volatile altword *u2 = (volatile altword *)p2;
	altword a = 0;
	size /= sizeof(altword);
	while (size--)
	  a |= (*u1++ ^ *u2++);
	return bool(a);
      }
    else
      {
	//OPENVPN_LOG("*** MEMCMP CHAR " << (size_t(p1) & (sizeof(altword)-1)) << ' ' << (size_t(p2) & (sizeof(altword)-1)) << ' ' << size);
	volatile unsigned char *v1 = (volatile unsigned char *)p1;
	volatile unsigned char *v2 = (volatile unsigned char *)p2;
	unsigned char a = 0;
	while (size--)
	  a |= (*v1++ ^ *v2++);
	return bool(a);
      }
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_MEMCMP_H
