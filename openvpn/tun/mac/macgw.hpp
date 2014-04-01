//
//  macgw.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TUN_MAC_MACGW_H
#define OPENVPN_TUN_MAC_MACGW_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/apple/scdynstore.hpp>
#include <openvpn/applecrypto/cf/cfhelper.hpp>

namespace openvpn {
  struct MacGWInfo
  {
    struct Variant
    {
      friend struct MacGWInfo;
    public:
      bool defined() const {
	return !iface.empty() && router.defined();
      }

      std::string to_string() const
      {
	return iface + '/' + router.to_string();
      }

      std::string iface;
      IP::Addr router;

    private:
      Variant() {}

      Variant(const IP::Addr::Version v, const CF::DynamicStore& dstore)
      {
	const std::string key = std::string("State:/Network/Global/IP") + IP::Addr::version_string_static(v);
	const CF::Dict d(CF::DynamicStoreCopyDict(dstore, key));
	iface = CF::dict_get_str(d, "PrimaryInterface");
	const std::string addr = CF::dict_get_str(d, "Router");
	if (!addr.empty())
	  router = IP::Addr::from_string(addr, "MacGWInfo::Variant", v);
	else
	  router.reset();
      }
    };

    MacGWInfo()
    {
      const CF::DynamicStore ds(SCDynamicStoreCreate(kCFAllocatorDefault,
						     CFSTR("MacGWInfo"),
						     NULL,
						     NULL));
      v4 = Variant(IP::Addr::V4, ds);
      v6 = Variant(IP::Addr::V6, ds);
    }

    std::string to_string() const
    {
      return "IPv4=" + v4.to_string() + " IPv6=" + v6.to_string();
    }

    Variant v4;
    Variant v6;
  };
}

#endif
