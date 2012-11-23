//
//  hash.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
