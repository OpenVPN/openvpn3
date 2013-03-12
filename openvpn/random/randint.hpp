//
//  randint.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_RANDOM_RANDINT_H
#define OPENVPN_RANDOM_RANDINT_H

#include <openvpn/common/exception.hpp>
#include <openvpn/random/boostrand.hpp>
#include <openvpn/random/randtype.hpp>

namespace openvpn {

  // Return a RandomIntBase object that has been seeded using provided random API (RAND_API)
  template <typename RAND_API>
  class RandomInt : public RandomIntBase
  {
  public:
    RandomInt(RAND_API& rng) : RandomIntBase(rand_type<unsigned int, RAND_API>(rng)) {}
  };

} // namespace openvpn

#endif
