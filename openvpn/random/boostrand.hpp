//
//  boostrand.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Non-cryptographic random number generator based on boost::mt19937

#ifndef OPENVPN_RANDOM_BOOSTRAND_H
#define OPENVPN_RANDOM_BOOSTRAND_H

#include <boost/random.hpp>

namespace openvpn {

  class RandomIntBase
  {
  public:
    typedef unsigned int type;

    RandomIntBase(type seed) : rng_(seed) {}
    RandomIntBase() {} // deterministic sequence

    type randrange(const type end)
    {
      return rng_() % end;
    }

  private:
    boost::mt19937 rng_;
  };

} // namespace openvpn

#endif // OPENVPN_RANDOM_BOOSTRAND_H
