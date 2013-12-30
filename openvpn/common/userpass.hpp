//
//  userpass.hpp
//  OpenVPN
//
//  Copyright (c) 2013 OpenVPN Technologies, Inc. All rights reserved.
//

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
