//
//  tlsver.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Parse the tls-version-min option.

#ifndef OPENVPN_SSL_TLSVER_H
#define OPENVPN_SSL_TLSVER_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn {
  namespace TLSVersion {
    enum Type {
      V1_0=0,
      V1_1,
      V1_2
    };

    inline Type parse_tls_version_min(const OptionList& opt, const Type max_version) {
      const Option* o = opt.get_ptr("tls-version-min");
      if (o)
	{
	  const std::string& ct = o->get_optional(1, 16);
	  if (ct == "1.0" && V1_0 <= max_version)
	    return V1_0;
	  else if (ct == "1.1" && V1_1 <= max_version)
	    return V1_1;
	  else if (ct == "1.2" && V1_2 <= max_version)
	    return V1_2;
	  else if (o->get_optional(2, 16) == "or-highest")
	    return max_version;
	  else
	    throw option_error("tls-version-min: unrecognized TLS version");
	}
      return V1_0;
    }
  }
}

#endif
