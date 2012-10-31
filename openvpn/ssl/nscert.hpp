//
//  nscert.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_SSL_NSCERT_H
#define OPENVPN_SSL_NSCERT_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn {
  namespace NSCert {
    enum Type {
      NONE,
      CLIENT,
      SERVER
    };

    inline Type ns_cert_type(const OptionList& opt) {
      const Option* o = opt.get_ptr("ns-cert-type");
      if (o)
	{
	  const std::string& ct = o->get_optional(1);
	  if (ct == "server")
	    return SERVER;
	  else if (ct == "client")
	    return CLIENT;
	  else
	    throw option_error("ns-cert-type must be 'client' or 'server'");
	}
      return NONE;
    }
  }
}

#endif
