//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_COMMON_INOTIFY_H
#define OPENVPN_COMMON_INOTIFY_H

#include <sys/inotify.h>

#include <string>

namespace openvpn {
  namespace INotify {
    inline std::string mask_to_string(const uint32_t mask)
    {
      std::string ret;

      if (mask & IN_ACCESS)
	ret += "|IN_ACCESS";
      if (mask & IN_ATTRIB)
	ret += "|IN_ATTRIB";
      if (mask & IN_CLOSE_WRITE)
	ret += "|IN_CLOSE_WRITE";
      if (mask & IN_CLOSE_NOWRITE)
	ret += "|IN_CLOSE_NOWRITE";
      if (mask & IN_CREATE)
	ret += "|IN_CREATE";
      if (mask & IN_DELETE)
	ret += "|IN_DELETE";
      if (mask & IN_DELETE_SELF)
	ret += "|IN_DELETE_SELF";
      if (mask & IN_MODIFY)
	ret += "|IN_MODIFY";
      if (mask & IN_MOVE_SELF)
	ret += "|IN_MOVE_SELF";
      if (mask & IN_MOVED_FROM)
	ret += "|IN_MOVED_FROM";
      if (mask & IN_MOVED_TO)
	ret += "|IN_MOVED_TO";
      if (mask & IN_OPEN)
	ret += "|IN_OPEN";

      if (ret.length())
	return ret.substr(1);
      else
	return std::string();
    }
  }
}
#endif
