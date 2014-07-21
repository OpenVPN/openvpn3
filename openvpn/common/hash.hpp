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

#ifndef OPENVPN_COMMON_HASH_H
#define OPENVPN_COMMON_HASH_H

#include <openvpn/common/types.hpp>

namespace openvpn {

  // A hasher that combines a data hash with a stateful seed.
  template <typename T>
  class HashInitialSeed
  {
  public:
    HashInitialSeed(std::size_t seed) : seed_(seed) {}

    std::size_t operator()(const T& obj) const
    {
      std::size_t seed = seed_;
      boost::hash_combine(seed, obj);
      return seed;
    }

  private:
    std::size_t seed_;
  };
}

#endif
