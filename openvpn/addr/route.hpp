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

#ifndef OPENVPN_ADDR_ROUTE_H
#define OPENVPN_ADDR_ROUTE_H

#include <string>
#include <sstream>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn {
  namespace IP {
    // Basic route object
    template <typename ADDR>
    struct RouteType
    {
      typedef ADDR Addr;

      ADDR addr;
      unsigned int prefix_len;

      OPENVPN_EXCEPTION(route_error);

      RouteType()
	: prefix_len(0)
      {
      }

      RouteType(const std::string& rtstr, const char *title = NULL)
	: RouteType(RouteType::from_string(rtstr, title))
      {
      }

      RouteType(const ADDR& addr_arg, const unsigned int prefix_len_arg)
	: addr(addr_arg),
	  prefix_len(prefix_len_arg)
      {
      }

      static RouteType from_string(const std::string& rtstr, const char *title = NULL)
      {
	RouteType r;
	std::vector<std::string> pair;
	pair.reserve(2);
	Split::by_char_void<std::vector<std::string>, NullLex, Split::NullLimit>(pair, rtstr, '/', 0, 1);
	r.addr = ADDR::from_string(pair[0], title);
	if (pair.size() >= 2)
	  {
	    r.prefix_len = parse_number_throw<unsigned int>(pair[1], "prefix length");
	    if (r.prefix_len > r.addr.size())
	      throw route_error(rtstr + ": bad prefix len");
	  }
	else
	  r.prefix_len = r.addr.size();
	return r;
      }

      IP::Addr::Version version() const
      {
	return addr.version();
      }

      ADDR netmask() const
      {
	return ADDR::netmask_from_prefix_len(version(), prefix_len);
      }

      size_t extent() const
      {
	return netmask().extent_from_netmask().to_ulong();
      }

      bool is_canonical() const
      {
	return (addr & netmask()) == addr;
      }

      void force_canonical()
      {
	addr = addr & netmask();
      }

      std::string to_string() const
      {
	std::ostringstream os;
	os << addr.to_string() << '/' << prefix_len;
	return os.str();
      }

      bool operator==(const RouteType& other) const
      {
	return prefix_len == other.prefix_len && addr == other.addr;
      }
    };

    // Compute hash value of Route
    template <typename ADDR>
    inline std::size_t hash_value(const RouteType<ADDR>& route)
    {
      std::size_t seed = 0;
      boost::hash_combine(seed, route.addr);
      boost::hash_combine(seed, route.prefix_len);
      return seed;
    }

    typedef RouteType<IP::Addr> Route;
    typedef RouteType<IPv4::Addr> Route4;
    typedef RouteType<IPv6::Addr> Route6;

    OPENVPN_OSTREAM(Route, to_string);
    OPENVPN_OSTREAM(Route4, to_string);
    OPENVPN_OSTREAM(Route6, to_string);
  }
}

#endif
