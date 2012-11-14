//
//  kuparse.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_SSL_KUPARSE_H
#define OPENVPN_SSL_KUPARSE_H

#include <vector>
#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn {
  namespace KUParse {
    inline void remote_cert_tls(const OptionList& opt, std::vector<unsigned int>& ku, std::string& eku)
    {
      const Option* o = opt.get_ptr("remote-cert-tls");
      if (o)
	{
	  const std::string& ct = o->get_optional(1, 16);
	  if (ct == "server")
	    {
	      ku.push_back(0xa0);
	      ku.push_back(0x88);
	      eku = "TLS Web Server Authentication";
	    }
	  else if (ct == "client")
	    {
	      ku.push_back(0x80);
	      ku.push_back(0x08);
	      ku.push_back(0x88);
	      eku = "TLS Web Client Authentication";
	    }
	  else
	    throw option_error("remote-cert-tls must be 'client' or 'server'");	      
	}
    }

    inline void remote_cert_ku(const OptionList& opt, std::vector<unsigned int>& ku)
    {
      const Option* o = opt.get_ptr("remote-cert-ku");
      if (o)
	{
	  if (o->empty())
	    throw option_error("remote-cert-ku: no hex values specified");
	  else if (o->size() >= 64)
	    throw option_error("remote-cert-ku: too many parameters");
	  else
	    {
	      try {
		for (size_t i = 1; i < o->size(); ++i)
		  ku.push_back(parse_hex_number<unsigned int>(o->get(i, 16).c_str()));
	      }
	      catch (parse_hex_error& e)
		{
		  throw option_error("remote-cert-ku: error parsing hex value list");
		}
	    }
	}
    }

    inline void remote_cert_eku(const OptionList& opt, std::string& eku)
    {
      const Option* o = opt.get_ptr("remote-cert-eku");
      if (o)
	eku = o->get(1, 256);
    }
  }
}

#endif
