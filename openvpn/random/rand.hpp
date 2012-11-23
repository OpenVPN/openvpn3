//
//  rand.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_RANDOM_RAND_H
#define OPENVPN_RANDOM_RAND_H

#include <openvpn/common/exception.hpp>
#include <openvpn/random/boostrand.hpp>

namespace openvpn {

  // Given a random API (RAND_API), return a T object that has been filled with random bits
  template <typename T, typename RAND_API>
  inline T rand_type(RAND_API& rng)
  {
    T ret;
    rng.rand_bytes((unsigned char *)&ret, sizeof(ret));
    return ret;
  }

  // Return a RandomIntBase object that has been seeded using provided random API (RAND_API)
  template <typename RAND_API>
  class RandomInt : public RandomIntBase
  {
  public:
    RandomInt(RAND_API& rng) : RandomIntBase(rand_type<unsigned int, RAND_API>(rng)) {}
  };

} // namespace openvpn

#endif // OPENVPN_RANDOM_RAND_H
