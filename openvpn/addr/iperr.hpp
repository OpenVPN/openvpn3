//
//  iperr.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_ADDR_IPERR_H
#define OPENVPN_ADDR_IPERR_H

#include <string>

#include <boost/asio.hpp>

namespace openvpn {
  namespace IP {
    namespace internal {
      // Called internally by IP, IPv4, and IPv6 classes
      inline std::string format_error(const std::string& ipstr, const char *title, const char *ipver, const boost::system::error_code& ec)
      {
	std::string err = "error parsing";
	if (title)
	  {
	    err += ' ';
	    err += title;
	  }
	err += " IP";
	err += ipver;
	err += " address '";
	err += ipstr;
	err += "' : ";
	err += ec.message();
	return err;
      }
    }
  }
}

#endif
