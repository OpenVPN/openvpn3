//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

// Denote the data in an HTTP header

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

      const std::string get_value(const std::string& key) const
      {
	const Header* h = get(key);
	if (h)
	  return h->value;
	else
	  return "";
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
