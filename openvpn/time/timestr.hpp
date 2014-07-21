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

// Function to return the current date/time as a string.

#ifndef OPENVPN_TIME_TIMESTR_H
#define OPENVPN_TIME_TIMESTR_H

#include <cstring> // for std::strlen
#include <time.h>

#include <openvpn/common/types.hpp>

namespace openvpn {

  inline const char *date_time()
  {
    const time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    char *ret = asctime(lt);
    const int len = std::strlen(ret);
    if (len > 0 && ret[len-1] == '\n')
      ret[len-1] = '\0';
    return ret;
  }
}

#endif
