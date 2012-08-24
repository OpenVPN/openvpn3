//
//  tunspec.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TUN_TUNSPEC_H
#define OPENVPN_TUN_TUNSPEC_H

#include <string>

#include <openvpn/common/split.hpp>

namespace openvpn {

  struct ParseTunSpec
  {
    OPENVPN_EXCEPTION(bad_tun_spec);

    ParseTunSpec(const std::string& tun_spec)
      : ipv6(false)
    {
      std::vector<std::string> s = split_by_char<std::vector<std::string>, NullLex>(tun_spec, '/');
      if (s.size() == 1)
	{
	  tun_name = s[0];
	}
      else if (s.size() == 2)
	{
	  tun_name = s[0];
	  if (s[1] == "v4")
	    ipv6 = false;
	  else if (s[1] == "v6")
	    ipv6 = true;
	  else
	    throw bad_tun_spec();
	}
      else
	throw bad_tun_spec();
    }
    bool ipv6;
    std::string tun_name;
  };

} // namespace openvpn

#endif // OPENVPN_TUN_TUNSPEC_H
