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

// Parse the tls-version-min option.

#ifndef OPENVPN_SSL_TLSVER_H
#define OPENVPN_SSL_TLSVER_H

#include <string>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn {
  namespace TLSVersion {
    enum Type {
      UNDEF=0,
      V1_0,
      V1_1,
      V1_2
    };

    const std::string to_string(const Type version)
    {
      switch (version)
	{
	case UNDEF:
	  return "UNDEF";
	case V1_0:
	  return "V1_0";
	case V1_1:
	  return "V1_1";
	case V1_2:
	  return "V1_2";
	default:
	  return "???";
	}
    }

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
      return UNDEF;
    }

    inline void apply_override(Type& tvm, const std::string& override)
    {
      //const Type orig = tvm;
      if (override.empty() || override == "default")
	;
      else if (override == "disabled")
	tvm = UNDEF;
      else if (override == "tls_1_0")
	tvm = V1_0;
      else if (override == "tls_1_1")
	tvm = V1_1;
      else if (override == "tls_1_2")
	tvm = V1_2;
      else
	throw option_error("tls-version-min: unrecognized override string");

      //OPENVPN_LOG("*** TLS-version-min before=" << to_string(orig) << " override=" << override << " after=" << to_string(tvm)); // fixme
    }
  }
}

#endif
