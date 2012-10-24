//
//  header.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.

#ifndef OPENVPN_HTTP_HEADER_H
#define OPENVPN_HTTP_HEADER_H

#include <string>
#include <sstream>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>

namespace openvpn {
  namespace HTTP {

    struct Header {
      Header() {}
      Header(const std::string& name_arg, const std::string& value_arg)
	: name(name_arg), value(value_arg) {}

      std::string to_string() const
      {
	std::ostringstream out;
	out << name << '=' << value;
	return out.str();
      }

      std::string name;
      std::string value;
    };

    struct HeaderList : public std::vector<Header> {
      const Header* get(const std::string& key) const
      {
	for (std::vector<Header>::const_iterator i = begin(); i != end(); ++i)
	  {
	    const Header& h = *i;
	    if (string::strcasecmp(key, h.name) == 0)
	      return &h;
	  }
	return NULL;
      }

      std::string to_string() const
      {
	std::ostringstream out;
	for (size_t i = 0; i < size(); ++i)
	  out << '[' << i << "] " << (*this)[i].to_string() << std::endl;
	return out.str();
      }      
    };

  }
}

#endif
