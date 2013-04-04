//
//  endian.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Test for machine endiannes

#ifndef OPENVPN_COMMON_ENDIAN_H
#define OPENVPN_COMMON_ENDIAN_H

#include <boost/detail/endian.hpp>

namespace openvpn {
  namespace Endian {
#   ifdef BOOST_LITTLE_ENDIAN
    inline size_t e4(const size_t v)
    {
      return v;
    }
    inline size_t e4rev(const size_t v)
    {
      return 3-v;
    }
    inline size_t e2(const size_t v)
    {
      return v;
    }
    inline size_t e2rev(const size_t v)
    {
      return 1-v;
    }
#   elif BOOST_BIG_ENDIAN
    inline size_t e4rev(const size_t v)
    {
      return v;
    }
    inline size_t e4(const size_t v)
    {
      return 3-v;
    }
    inline size_t e2rev(const size_t v)
    {
      return v;
    }
    inline size_t e2(const size_t v)
    {
      return 1-v;
    }
#   else
#   error One of BOOST_LITTLE_ENDIAN or BOOST_BIG_ENDIAN must be defined
#   endif
  }
} // namespace openvpn

#endif // OPENVPN_COMMON_ENDIAN_H
