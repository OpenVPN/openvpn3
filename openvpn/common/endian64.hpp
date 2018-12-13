//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.

#pragma once

#include <cstdint>

#include <openvpn/common/endian_platform.hpp>

namespace openvpn {
  namespace Endian {
    inline std::uint64_t rev64(const std::uint64_t value)
    {
#ifdef OPENVPN_LITTLE_ENDIAN
#ifdef __clang__
      return __builtin_bswap64(value);
#else
      return __bswap_constant_64(value);
#endif
#else
      return value;
#endif
    }
  }
}
