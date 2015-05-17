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

#ifndef OPENVPN_TRANSPORT_TRANSMAP_H
#define OPENVPN_TRANSPORT_TRANSMAP_H

#include <cstring>
#include <string>
#include <sstream>

#include <boost/unordered_map.hpp>

#include <openvpn/common/size.hpp>
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

      std::string to_string()
      {
	std::ostringstream os;
	os << '[' << addr << "]:" << port;
	return os.str();
      }

      template <typename ASIO_ENDPOINT>
      static Endpoint from_asio(const ASIO_ENDPOINT& ae)
      {
	Endpoint ret;
	ret.addr = IP::Addr::from_asio(ae.address());
	ret.port = ae.port();
	return ret;
      }
    };

    // Compute hash value of our Endpoint (above)
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
      typedef typename map_type::iterator iterator;
      typedef typename map_type::const_iterator const_iterator;

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
	map[r] = vp;
      }

      const_iterator begin() const
      {
	return map.begin();
      }

      const_iterator end() const
      {
	return map.end();
      }

      iterator find(const ENDPOINT& ep)
      {
	return map.find(ep);
      }

      iterator erase(const_iterator i)
      {
	return map.erase(i);
      }

      void clear()
      {
	map.clear();
      }

    private:
      size_t insertions_since_reap;
      HashInitialSeed<ENDPOINT> seed;
      map_type map;
    };

  }
}

#endif
