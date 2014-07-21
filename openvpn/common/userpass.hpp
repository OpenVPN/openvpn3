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

#ifndef OPENVPN_COMMON_USERPASS_H
#define OPENVPN_COMMON_USERPASS_H

#include <string>
#include <vector>

#include <openvpn/common/options.hpp>
#include <openvpn/common/splitlines.hpp>

namespace openvpn {

  inline bool parse_user_pass(const OptionList& options, const std::string& opt_name, std::vector<std::string>* user_pass)
    {
      const Option* auth_user_pass = options.get_ptr(opt_name);
      if (auth_user_pass)
	{
	  if (user_pass && auth_user_pass->size() == 2)
	    {
	      SplitLines in(auth_user_pass->get(1, 512 | Option::MULTILINE), 256);
	      for (int i = 0; in(true) && i < 2; ++i)
		user_pass->push_back(in.line_ref());
	    }
	  return true;
	}
      else
	return false;
    }

} // namespace openvpn

#endif
