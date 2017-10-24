//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.

#pragma once

#include <endian.h>    // __BYTE_ORDER
#include <cstdint>

namespace openvpn {
  namespace Endian {
    inline std::uint64_t rev64(const std::uint64_t value)
    {
#if __BYTE_ORDER == __LITTLE_ENDIAN
      return __bswap_constant_64(value);  // compiler-builtin
#else
      return value;
#endif
    }
  }
}
