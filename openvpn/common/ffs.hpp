//
//  ffs.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_FFS_H
#define OPENVPN_COMMON_FFS_H

// find_first_set: find the one-based position of the first 1 bit in
// a word (scanning from least significant bit to most significant)

// find_last_set: find the one-based position of the last 1 bit in
// a word (scanning from most significant bit to least significant)

namespace openvpn {

#if defined(__GNUC__)

  inline int find_first_set(unsigned int v)
  {
    if (!v)
      return 0;
    return __builtin_ffs(v);
  }

  inline int find_last_set(unsigned int v)
  {
    if (!v)
      return 0;
    return 32 - __builtin_clz(v);
  }

#elif defined(_MSC_VER)

#include <intrin.h>

  inline int find_first_set(unsigned int x)
  {
    if (!x)
      return 0;
    unsigned int r = 0;
    _BitScanForward((unsigned long *)&r, x);
    return r + 1;
  }

  inline int find_last_set(unsigned int x)
  {
    if (!x)
      return 0;
    unsigned int r = 0;
    _BitScanReverse((unsigned long *)&r, x);
    return r + 1;
  }

#else
#error no find_first_set / find_last_set implementation for this platform
#endif

} // namespace openvpn

#endif // OPENVPN_COMMON_FFS_H
