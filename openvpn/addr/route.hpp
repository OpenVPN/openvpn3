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
#include <vector>
#include <cstdint> // for std::uint32_t

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/hash.hpp>
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
      std::uint32_t mark;

      OPENVPN_EXCEPTION(route_error);

      RouteType()
	: prefix_len(0),
	  mark(0)
      {
      }

      RouteType(const std::string& rtstr, const char *title = nullptr)
	: RouteType(RouteType::from_string(rtstr, title))
      {
      }

      RouteType(const std::string& rtstr, const std::string& title)
	: RouteType(RouteType::from_string(rtstr, title.c_str()))
      {
      }

      RouteType(const ADDR& addr_arg,
		const unsigned int prefix_len_arg,
		const std::uint32_t mark_arg = 0)
	: addr(addr_arg),
	  prefix_len(prefix_len_arg),
	  mark(mark_arg)
      {
      }

      static RouteType from_string(const std::string& rtstr, const char *title = nullptr)
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

      static RouteType from_string_prefix(const std::string& addrstr,
					  unsigned int prefix_len,
					  const char *title = nullptr)
      {
	RouteType r;
	r.addr = ADDR::from_string(addrstr, title);
	r.prefix_len = prefix_len;
	return r;
      }

      IP::Addr::Version version() const
      {
	return addr.version();
      }

      IP::Addr::VersionMask version_mask() const
      {
	return addr.version_mask();
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

      bool is_host() const
      {
	return addr.defined() && prefix_len == addr.size();
      }

      bool contains(const ADDR& a) const // assumes canonical address/routes
      {
	if (addr.defined() && addr.version() == a.version())
	  return (a & netmask()) == addr;
	else
	  return false;
      }

      bool contains(const RouteType& r) const // assumes canonical routes
      {
	return contains(r.addr) && r.prefix_len >= prefix_len;
      }

      bool split(RouteType& r1, RouteType& r2) const // assumes we are canonical
      {
	if (!is_host())
	  {
	    const unsigned int newpl = prefix_len + 1;
	    r1.addr = addr;
	    r1.prefix_len = newpl;

	    r2.addr = addr + ADDR::netmask_from_prefix_len(addr.version(), newpl).extent_from_netmask();
	    r2.prefix_len = newpl;

	    return true;
	  }
	return false;
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

#if HAVE_HASH_COMBINE
      std::size_t hash_value() const
      {
	std::size_t seed = 0;
	Hash::combine(seed, addr);
	Hash::combine(seed, prefix_len);
	return seed;
      }
    };
#endif

    template <typename ADDR>
    struct RouteTypeList : public std::vector<RouteType<ADDR>>
    {
      typedef std::vector< RouteType<ADDR> > Base;

      OPENVPN_EXCEPTION(route_list_error);

      std::string to_string() const
      {
	std::ostringstream os;
	for (typename Base::const_iterator i = Base::begin(); i != Base::end(); ++i)
	  os << i->to_string() << std::endl;
	return os.str();
      }

      IP::Addr::VersionMask version_mask() const
      {
	IP::Addr::VersionMask mask = 0;
	for (typename Base::const_iterator i = Base::begin(); i != Base::end(); ++i)
	  mask |= i->version_mask();
	return mask;
      }

      void verify_canonical() const
      {
	for (typename Base::const_iterator i = Base::begin(); i != Base::end(); ++i)
	  if (!i->is_canonical())
	    throw route_list_error("route not canonical: " + i->to_string());
      }
    };

    typedef RouteType<IP::Addr> Route;
    typedef RouteType<IPv4::Addr> Route4;
    typedef RouteType<IPv6::Addr> Route6;

    typedef RouteTypeList<IP::Addr> RouteList;
    typedef RouteTypeList<IPv4::Addr> Route4List;
    typedef RouteTypeList<IPv6::Addr> Route6List;

    OPENVPN_OSTREAM(Route, to_string);
    OPENVPN_OSTREAM(Route4, to_string);
    OPENVPN_OSTREAM(Route6, to_string);

    OPENVPN_OSTREAM(RouteList, to_string);
    OPENVPN_OSTREAM(Route4List, to_string);
    OPENVPN_OSTREAM(Route6List, to_string);
  }
}

#endif
