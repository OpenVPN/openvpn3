//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_AUTH_VALIDATE_CREDS_H
#define OPENVPN_AUTH_VALIDATE_CREDS_H

#include <openvpn/common/unicode.hpp>

namespace openvpn {
  // Authentication credential (username, password, or response) must
  // satisfy these constraints:
  //
  // 1. must be a valid UTF-8 string
  // 2. must not contain control or space characters
  // 3. length must be <= 256 unicode characters
  //
  // Note that we don't check that string is non-empty here,
  // callers should do this themselves if necessary.
  template <typename STRING>
  inline bool validate_auth_cred(const STRING& cred)
  {
    return Unicode::is_valid_utf8(cred, 256 | Unicode::UTF8_NO_CTRL | Unicode::UTF8_NO_SPACE);
  }
}

#endif
