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

#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <string>

#include <openvpn/common/file.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {
  inline double cpu_time(const bool thread=false)
  {
    try {
      std::string stat_fn;
      if (thread)
	stat_fn = "/proc/" + std::to_string(::getpid()) + "/task/" + std::to_string(::syscall(SYS_gettid)) +  "/stat";
      else
	stat_fn = "/proc/" + std::to_string(::getpid()) + "/stat";
      const std::string stat_str = read_text_simple(stat_fn);
      auto sv = string::split(stat_str, ' ');
      if (sv.size() < 15)
	throw Exception(stat_fn + " must have at least 15 fields");
      const unsigned long utime = parse_number_throw<unsigned long>(sv[13], "error parsing utime");
      const unsigned long stime = parse_number_throw<unsigned long>(sv[14], "error parsing stime");
      const long denom = ::sysconf(_SC_CLK_TCK);
      if (denom < 0)
	throw Exception("sysconf(_SC_CLK_TCK) failed");
      return double(utime + stime) / double(denom);
    }
    catch (const std::exception& e)
      {
	//OPENVPN_LOG("cpu_time exception: " << e.what());
	return -1.0;
      }
  }
}
