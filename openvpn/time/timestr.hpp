//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

// Function to return the current date/time as a string.

#ifndef OPENVPN_TIME_TIMESTR_H
#define OPENVPN_TIME_TIMESTR_H

#include <string>
#include <cstring> // for std::strlen
#include <time.h>

#include <openvpn/common/types.hpp>

namespace openvpn {

  inline std::string date_time(const time_t now)
  {
    struct tm lt;
    char buf[64];

    if (!localtime_r(&now, &lt))
      return "LOCALTIME_ERROR";
    if (!asctime_r(&lt, buf))
      return "ASCTIME_ERROR";
    const int len = std::strlen(buf);
    if (len > 0 && buf[len-1] == '\n')
      buf[len-1] = '\0';
    return std::string(buf);
  }

  inline std::string date_time()
  {
    return date_time(time(NULL));
  }
}

#endif
