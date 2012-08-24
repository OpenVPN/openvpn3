//
//  transmap.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TRANSPORT_TRANSMAP_H
#define OPENVPN_TRANSPORT_TRANSMAP_H

#include <cstring>

#include <boost/unordered_map.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/hash.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn {
  namespace TransportMap {

    // Basic transport endpoint object, for example might be used
    // on server to record the address of a remote UDP client.
    template <typename ADDR>
    struct Endpoint
    {
      typedef ADDR Addr;

      ADDR addr;
      unsigned short port;

      bool operator==(const Endpoint& other) const
      {
	return port == other.port && addr == other.addr;
      }
    };

    // Compute hash value of Endpoint
    template <typename ADDR>
    inline std::size_t hash_value(const Endpoint<ADDR>& endpoint)
    {
      std::size_t seed = 0;
      boost::hash_combine(seed, endpoint.addr);
      boost::hash_combine(seed, endpoint.port);
      return seed;
    }

    template <typename ENDPOINT, typename VALUE>
    class Map
    {
      typedef boost::unordered_map<ENDPOINT, typename VALUE::Ptr, HashInitialSeed<ENDPOINT> > map_type;

    public:
      enum {
	INITIAL_BUCKETS = 2048,
	REAP_TRIGGER = 1024,
      };

      Map(const std::size_t initial_seed)
	: insertions_since_reap(0),
	  seed(initial_seed),
	  map(INITIAL_BUCKETS, seed)
      {
      }

      void add(const ENDPOINT& r, const typename VALUE::Ptr& vp)
      {
	if (++insertions_since_reap > REAP_TRIGGER)
	  reap();
	map[r] = vp;
      }

      void reap()
      {
	insertions_since_reap = 0;
	typename map_type::const_iterator i = map.begin();
	while (i != map.end())
	  {
	    if (i->second->defined())
	      ++i;
	    else
	      map.erase(i++);
	  }
      }

    private:
      size_t insertions_since_reap;
      HashInitialSeed<ENDPOINT> seed;
      map_type map;
    };

  }
}

#endif
