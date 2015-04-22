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
#include <sys/time.h>
#include <stdio.h>
#include <ctype.h>

#include <openvpn/common/types.hpp>

namespace openvpn {

  inline std::string date_time(const time_t t)
  {
    struct tm lt;
    char buf[64];

    if (!localtime_r(&t, &lt))
      return "LOCALTIME_ERROR";
    if (!asctime_r(&lt, buf))
      return "ASCTIME_ERROR";
    const int len = std::strlen(buf);
    if (len > 0 && buf[len-1] == '\n')
      buf[len-1] = '\0';
    return std::string(buf);
  }

  // msecs == false : Tue Feb 17 01:24:30 2015
  // msecs == true  : Tue Feb 17 01:24:30.123 2015
  inline std::string date_time(const struct timeval *tv, const bool msecs)
  {
    const std::string dt = date_time(tv->tv_sec);
    if (msecs)
      {
	// find correct position in string to insert milliseconds
	const size_t pos = dt.find_last_of(':');
	if (pos != std::string::npos
	    && pos + 3 < dt.length()
	    && isdigit(dt[pos+1])
	    && isdigit(dt[pos+2])
	    && isspace(dt[pos+3]))
	  {
	    char ms[5];
	    ::snprintf(ms, sizeof(ms), ".%03u", static_cast<unsigned int>(tv->tv_usec / 1000));
	    return dt.substr(0, pos+3) + ms + dt.substr(pos+3);
	  }
      }
    return dt;
  }

  inline std::string date_time()
  {
    struct timeval tv;
    if (::gettimeofday(&tv, NULL) < 0)
      {
	tv.tv_sec = 0;
	tv.tv_usec = 0;
      }
    return date_time(&tv, true);
  }

  inline std::string date_time_rfc822(const time_t t)
  {
    struct tm lt;
    char buf[64];

    if (!gmtime_r(&t, &lt))
      return "";
    if (!strftime(buf, sizeof(buf),
		  "%a, %d %b %Y %T %Z",
		  &lt))
      return "";
    return std::string(buf);
  }

  inline std::string date_time_rfc822()
  {
    return date_time_rfc822(time(NULL));
  }
}

#endif
