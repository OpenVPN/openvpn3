//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_COMMON_HASH_H
#define OPENVPN_COMMON_HASH_H

#include <cstring> // for std::strlen
#include <cstdint> // for std::uint32_t, uint64_t
#include <functional>

#include <openvpn/common/size.hpp>

#define OPENVPN_HASH_METHOD(T, meth)			\
  namespace std {					\
    template <>						\
    struct hash<T>					\
    {							\
      inline std::size_t operator()(const T& obj) const	\
      {							\
        return obj.meth();				\
      }							\
    };							\
  }

namespace openvpn {
  namespace Hash {

    void combine_data(std::size_t& seed, const void *data, std::size_t size);

    template <class T>
    inline void combine(std::size_t& seed, const T& v)
    {
      std::hash<T> hasher;
      seed ^= hasher(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
    }

    inline void combine(std::size_t& seed, const char *str)
    {
      combine_data(seed, str, std::strlen(str));
    }

    template<typename T, typename... Args>
    inline void combine(std::size_t& seed, const T& first, Args... args)
    {
      combine(seed, first);
      combine(seed, args...);
    }

    template<typename... Args>
    inline std::size_t value(Args... args)
    {
      std::size_t hash = 0;
      combine(hash, args...);
      return hash;
    }

    // A hasher that combines a data hash with a stateful seed.
    template <typename T>
    class InitialSeed
    {
    public:
      InitialSeed(std::size_t seed) : seed_(seed) {}

      std::size_t operator()(const T& obj) const
      {
	std::size_t seed = seed_;
	combine(seed, obj);
	return seed;
      }

    private:
      std::size_t seed_;
    };

    inline void combine_data(std::size_t& seed, const void *data, std::size_t size)
    {
      while (size >= sizeof(std::uint32_t))
	{
	  combine(seed, static_cast<const std::uint32_t*>(data)[0]);
	  data = static_cast<const std::uint8_t*>(data) + sizeof(std::uint32_t);
	  size -= sizeof(std::uint32_t);
	}
      switch (size)
	{
	case 1:
	  combine(seed, static_cast<const std::uint8_t*>(data)[0]);
	  break;
	case 2:
	  combine(seed, static_cast<const std::uint16_t*>(data)[0]);
	  break;
	case 3:
	  combine(seed, static_cast<const std::uint16_t*>(data)[0]);
	  combine(seed, static_cast<const std::uint8_t*>(data)[2]);
	  break;
	}
    }
  }
}

#endif
