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

#ifndef OPENVPN_COMMON_USERPASS_H
#define OPENVPN_COMMON_USERPASS_H

#include <string>
#include <vector>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/file.hpp>

namespace openvpn {
  namespace UserPass {

    OPENVPN_EXCEPTION(creds_error);

    enum Flags {
      OPT_REQUIRED = (1<<0),
      USERNAME_REQUIRED = (1<<1),
      PASSWORD_REQUIRED = (1<<2),
      TRY_FILE = (1<<3),
    };

    inline bool parse(const OptionList& options,
		      const std::string& opt_name,
		      const unsigned int flags,
		      std::vector<std::string>* user_pass)
    {
      const Option* auth_user_pass = options.get_ptr(opt_name);
      if (!auth_user_pass)
	{
	  if (flags & OPT_REQUIRED)
	    throw creds_error(opt_name + " : credentials option missing");
	  return false;
	}
      if (auth_user_pass->size() != 2)
	{
	  if (flags & OPT_REQUIRED)
	    throw creds_error(opt_name + " : credentials option incorrectly specified");
	  return false;
	}

      std::string str = auth_user_pass->get(1, 1024 | Option::MULTILINE);
      if ((flags & TRY_FILE) && !string::is_multiline(str))
	str = read_text_utf8(str);
      SplitLines in(str, 1024);
      for (int i = 0; in(true) && i < 2; ++i)
	{
	  const std::string& line = in.line_ref();
	  if (user_pass)
	    user_pass->push_back(line);
	}
      return true;
    }

    inline void parse(const OptionList& options,
		      const std::string& opt_name,
		      const unsigned int flags,
		      std::string& user,
		      std::string& pass)
    {
      std::vector<std::string> up;
      up.reserve(2);
      parse(options, opt_name, flags, &up);
      if (up.size() >= 1)
	{
	  user = up[0];
	  if (up.size() >= 2)
	    pass = up[1];
	}
      if ((flags & USERNAME_REQUIRED) && string::is_empty(user))
	throw creds_error(opt_name + " : username empty");
      if ((flags & PASSWORD_REQUIRED) && string::is_empty(pass))
	throw creds_error(opt_name + " : password empty");
    }

    inline void parse(const std::string& path,
		      const unsigned int flags,
		      std::string& user,
		      std::string& pass)
    {
      user.clear();
      pass.clear();
      const std::string str = read_text_utf8(path);
      SplitLines in(str, 1024);
      if (in(true))
	{
	  user = in.line_ref();
	  if (in(true))
	    pass = in.line_ref();
	}
      if ((flags & USERNAME_REQUIRED) && string::is_empty(user))
	throw creds_error(path + " : username empty");
      if ((flags & PASSWORD_REQUIRED) && string::is_empty(pass))
	throw creds_error(path + " : password empty");
    }

  }
}

#endif
