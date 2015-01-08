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

#ifndef OPENVPN_COMMON_ENUMDIR_H
#define OPENVPN_COMMON_ENUMDIR_H

#include <sys/types.h>
#include <dirent.h>

#include <string>
#include <vector>
#include <utility>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/scoped_ptr.hpp>

namespace openvpn {
  OPENVPN_EXCEPTION(enum_dir_error);

  template <typename T>
  class FreeDIR {
  public:
    static void del(T* p)
    {
      // delete method for pointer returned by opendir
      closedir(p);
    }
  };

  std::vector<std::string> enum_dir(const std::string& dirname,
				    const size_t size_hint=0)
  {
    std::vector<std::string> ret;
    if (size_hint)
      ret.reserve(size_hint);
    ScopedPtr<DIR, FreeDIR> dir(opendir(dirname.c_str()));
    if (!dir.defined())
      throw enum_dir_error(dirname + ": cannot open directory");

    struct dirent *e;
    while ((e = readdir(dir())) != NULL)
      {
	std::string fn(e->d_name);
	if (fn != "." && fn != "..")
	  ret.push_back(std::move(fn));
      }

    return ret;
  }
}

#endif
