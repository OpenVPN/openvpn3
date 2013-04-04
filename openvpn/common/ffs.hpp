//
//  ffs.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_FFS_H
#define OPENVPN_COMMON_FFS_H

#include <strings.h> // for ffs (and fls on BSD)

#include <openvpn/common/platform.hpp>

namespace openvpn {
  // find the zero-based position of the first 1 bit in a word
  // (scanning from least significant bit to most significant)
  inline const int find_first_set(unsigned int v)
  {
    return ffs(v) - 1;
  }

  // find the one-based position of the last 1 bit in a word
  // (scanning from most significant bit to least significant)
  inline const int find_last_set(unsigned int v)
  {
#if defined(OPENVPN_PLATFORM_TYPE_APPLE)
    return fls(v); // apparently only BSD-based platforms have this
#else
    int r = 32;

    if (!v)
      return 0;
    if (!(v & 0xffff0000u)) {
      v <<= 16;
      r -= 16;
    }
    if (!(v & 0xff000000u)) {
      v <<= 8;
      r -= 8;
    }
    if (!(v & 0xf0000000u)) {
      v <<= 4;
      r -= 4;
    }
    if (!(v & 0xc0000000u)) {
      v <<= 2;
      r -= 2;
    }
    if (!(v & 0x80000000u)) {
      v <<= 1;
      r -= 1;
    }
    return r;
#endif
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_FFS_H
