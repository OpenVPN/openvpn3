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

#ifndef OPENVPN_ADDR_CIDRMAP_H
#define OPENVPN_ADDR_CIDRMAP_H

#include <cstring>

#include <boost/unordered_map.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/hash.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn {
  namespace CIDRMap {

    // Keep track of a set of route prefix lengths
    template <size_t N>
    class PrefixSet {
    public:
      OPENVPN_SIMPLE_EXCEPTION(cidr_index);

      PrefixSet()
      {
	reset();
      }

      void reset()
      {
	size = 0;
	std::memset(sparse, 0, sizeof(sparse));
      }

      void set(unsigned int i, const bool recompile_on_mod)
      {
	if (i > N)
	  throw cidr_index();
	if (!sparse[i])
	  {
	    sparse[i] = 1;
	    if (recompile_on_mod)
	      compile();
	  }
      }

      size_t n_prefixes() const { return size; }
      unsigned int get_prefix(const size_t i) const
      {
	if (i >= size)
	  throw cidr_index();
	return list[i];
      }

      void compile()
      {
	size = 0;
	for (int i = N; i >= 0; --i)
	  {
	    if (sparse[i])
	      list[size++] = (unsigned char)i;
	  }
      }

    private:
      size_t size;               // size of list
      unsigned char list[N+1];   // list of active prefixes in descending order
      unsigned char sparse[N+1]; // data indexed by prefix
    };

    // Basic route object
    template <typename ADDR>
    struct Route
    {
      typedef ADDR Addr;

      ADDR addr;
      unsigned int prefix_len;

      bool operator==(const Route& other) const
      {
	return prefix_len == other.prefix_len && addr == other.addr;
      }
    };

    // Compute hash value of Route
    template <typename ADDR>
    inline std::size_t hash_value(const Route<ADDR>& route)
    {
      std::size_t seed = 0;
      boost::hash_combine(seed, route.addr);
      boost::hash_combine(seed, route.prefix_len);
      return seed;
    }

    // Set of route prefix_lengths with iterator
    template <typename ROUTE>
    class RoutePrefixSet
    {
    public:
      class Iterator
      {
      public:
	Iterator(const RoutePrefixSet& parent_arg, const typename ROUTE::Addr& addr_arg)
	  : ps(parent_arg.ps), addr(addr_arg), index(0) {}

	bool next(ROUTE& r)
	{
	  if (index < ps.n_prefixes())
	    {
	      r.prefix_len = ps.get_prefix(index++);
	      r.addr = addr.network_addr(r.prefix_len);
	      return true;
	    }
	  else
	    return false;
	}

      private:
	const PrefixSet<ROUTE::Addr::SIZE>& ps;
	const typename ROUTE::Addr& addr;
	size_t index;
      };

      void reset()
      {
	ps.reset();
      }

      void add(const ROUTE& r, const bool recompile_on_mod)
      {
	ps.set(r.prefix_len, recompile_on_mod);
      }

      void compile()
      {
	ps.compile();
      }

    private:
      PrefixSet<ROUTE::Addr::SIZE> ps;
    };

    // Template specialization for RoutePrefixSet when IP::Addr is used
    // as the underlying type.
    // Since IP::Addr is run-time polymorphic (underlying address can be IPv4
    // or IPv6), we need some special handling here.
    template <>
    class RoutePrefixSet<Route<IP::Addr> >
    {
      typedef Route<IP::Addr> ROUTE;

    public:
      class Iterator
      {
      public:
	Iterator(const RoutePrefixSet& parent_arg, const typename ROUTE::Addr& addr_arg)
	  : parent(parent_arg), addr(addr_arg), index(0) {}

	bool next(ROUTE& r)
	{
	  if (addr.version() == IP::Addr::V4)
	    {
	      if (index < parent.ps_v4.n_prefixes())
		{
		  r.prefix_len = parent.ps_v4.get_prefix(index++);
		  r.addr = addr.network_addr(r.prefix_len);
		  return true;
		}
	    }
	  else if (addr.version() == IP::Addr::V6)
	    {
	      if (index < parent.ps_v6.n_prefixes())
		{
		  r.prefix_len = parent.ps_v6.get_prefix(index++);
		  r.addr = addr.network_addr(r.prefix_len);
		  return true;
		}
	    }
	  return false;
	}

      private:
	const RoutePrefixSet& parent;
	const typename ROUTE::Addr& addr;
	size_t index;
      };

      RoutePrefixSet() : v4(false), v6(false) {}

      void reset()
      {
	if (v4)
	  ps_v4.reset();
	if (v6)
	  ps_v6.reset();
	v4 = v6 = false;
      }

      void add(const ROUTE& r, const bool recompile_on_mod)
      {
	if (r.addr.version() == IP::Addr::V4)
	  {
	    v4 = true;
	    ps_v4.set(r.prefix_len, recompile_on_mod);
	  }
	else if (r.addr.version() == IP::Addr::V6)
	  {
	    v6 = true;
	    ps_v6.set(r.prefix_len, recompile_on_mod);
	  }
      }

      void compile()
      {
	if (v4)
	  ps_v4.compile();
	if (v6)
	  ps_v6.compile();
      }

    private:
      bool v4, v6;
      PrefixSet<IPv4::Addr::SIZE> ps_v4;
      PrefixSet<IPv6::Addr::SIZE> ps_v6;
    };

    template <typename ROUTE, typename VALUE>
    class RoutingTable
    {
      typedef boost::unordered_map<ROUTE, typename VALUE::Ptr, HashInitialSeed<ROUTE> > map_type;

    public:
      enum {
	INITIAL_BUCKETS = 2048,
	REAP_TRIGGER = 1024,
      };

      RoutingTable(const std::size_t initial_seed)
	: insertions_since_reap(0),
	  seed(initial_seed),
	  map(INITIAL_BUCKETS, seed)
      {
      }

      void add(const ROUTE& r, const typename VALUE::Ptr& vp)
      {
	if (++insertions_since_reap > REAP_TRIGGER)
	  reap();
	map[r] = vp;
	prefix_set.add(r, true);
      }

      bool match(const typename ROUTE::Addr& addr, typename VALUE::Ptr& vp)
      {
	ROUTE r;
	typename RoutePrefixSet<ROUTE>::Iterator ri(prefix_set, addr);
	while (ri.next(r))
	  {
	    typename map_type::const_iterator i = map.find(r);
	    if (i != map.end() && i->second->defined())
	      {
		vp = i->second;
		return true;
	      }
	  }
	return false;
      }

      void reap()
      {
	insertions_since_reap = 0;
	prefix_set.reset();
	typename map_type::const_iterator i = map.begin();
	while (i != map.end())
	  {
	    if (i->second->defined())
	      {
		prefix_set.add(i->first, false);
		++i;
	      }
	    else
	      {
		i = map.erase(i);
	      }
	  }
	prefix_set.compile();
      }

    private:
      size_t insertions_since_reap;
      RoutePrefixSet<ROUTE> prefix_set;
      HashInitialSeed<ROUTE> seed;
      map_type map;
    };
  }
}

#endif
