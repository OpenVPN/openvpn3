//
//  olong.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_OLONG_H
#define OPENVPN_COMMON_OLONG_H

// opportunistic long -- 32 bits on 32-bit machines, and 64 bits
// on 64-bit machines.

namespace openvpn {
#if defined(_MSC_VER) && defined(_M_X64)
  typedef long long olong;
  typedef unsigned long long oulong;
#else
  typedef long olong;
  typedef unsigned long oulong;
#endif
}

#endif
