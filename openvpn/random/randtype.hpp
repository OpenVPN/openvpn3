//
//  randtype.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_RANDOM_RANDTYPE_H
#define OPENVPN_RANDOM_RANDTYPE_H

namespace openvpn {

  // Given a random API (RAND_API), return a T object that has been filled with random bits
  template <typename T, typename RAND_API>
  inline T rand_type(RAND_API& rng)
  {
    T ret;
    rng.rand_bytes((unsigned char *)&ret, sizeof(ret));
    return ret;
  }

} // namespace openvpn

#endif
