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

// A helper macro for setting up an arbitrary class
// to support stringstream concatenation using <<

#ifndef OPENVPN_COMMON_OSTREAM_H
#define OPENVPN_COMMON_OSTREAM_H

#include <ostream>
#include <string>

#define OPENVPN_OSTREAM(TYPE, TO_STRING) \
    template <typename Elem, typename Traits> \
    std::basic_ostream<Elem, Traits>& operator<<( \
      std::basic_ostream<Elem, Traits>& os, const TYPE& addr) \
    { \
      std::string s = addr.TO_STRING(); \
      os << s; \
      return os; \
    }

#endif // OPENVPN_COMMON_OSTREAM_H
