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

#ifndef OPENVPN_ADDR_POOL_H
#define OPENVPN_ADDR_POOL_H

#include <string>
#include <sstream>
#include <deque>

#include <boost/unordered_map.hpp>
#include <boost/assert.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/addr/range.hpp>

namespace openvpn {
  namespace IP {

    // Maintain a pool of IP addresses.
    // A should be IP::Addr, IPv4::Addr, or IPv6::Addr.
    template <typename A>
    class Pool
    {
    public:
      Pool() {}

      // Add range of addresses to pool (pool will own the addresses).
      void add_range(const Range<A>& range)
      {
	typename Range<A>::Iterator iter = range.iterator();
	while (iter.more())
	  {
	    const A& a = iter.addr();
	    add_addr(a);
	    iter.next();
	  }
      }

      // Add single address to pool (pool will own the address).
      void add_addr(const A& addr)
      {
	typename boost::unordered_map<A, bool>::const_iterator e = map.find(addr);
	if (e == map.end())
	  {
	    freelist.push_back(addr);
	    map[addr] = false;
	  }
      }

      // Return number of pool addresses currently in use.
      size_t n_in_use() const
      {
	return map.size() - freelist.size();
      }

      // Acquire an address from pool.  Returns true if successful,
      // with address placed in dest, or false if pool depleted.
      bool acquire_addr(A& dest)
      {
	while (true)
	  {
	    if (freelist.empty())
	      return false;
	    const A& a = freelist.front();
	    typename boost::unordered_map<A, bool>::iterator e = map.find(a);
	    BOOST_ASSERT(e != map.end()); // any address in freelist must exist in map
	    if (!e->second)
	      {
		e->second = true;
		dest = a;
		freelist.pop_front();
		return true;
	      }
	    freelist.pop_front();
	  }
      }

      // Acquire a specific address from pool, returning true if
      // successful, or false if the address is not available.
      bool acquire_specific_addr(const A& addr)
      {
	typename boost::unordered_map<A, bool>::iterator e = map.find(addr);
	if (e != map.end() && !e->second)
	  {
	    e->second = true;
	    return true;
	  }
	else
	  return false;
      }

      // Return a previously acquired address to the pool.  Does nothing if
      // (a) the address is owned by the pool and marked as free, or
      // (b) the address is not owned by the pool.
      void release_addr(const A& addr)
      {
	typename boost::unordered_map<A, bool>::iterator e = map.find(addr);
	if (e != map.end() && e->second)
	  {
	    freelist.push_back(addr);
	    e->second = false;
	  }
      }

      // DEBUGGING -- get the map load factor
      float load_factor() const { return map.load_factor(); }

    private:
      std::deque<A> freelist;
      boost::unordered_map<A, bool> map;
    };
  }
}

#endif
