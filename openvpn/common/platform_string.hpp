//
//  platform_string.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_PLATFORM_STRING_H
#define OPENVPN_COMMON_PLATFORM_STRING_H

#include <string>
#include <sstream>

#include <openvpn/common/version.hpp>
#include <openvpn/common/platform_name.hpp>

namespace openvpn {
  inline std::string platform_string()
  {
    std::ostringstream os;

    os << "OpenVPN core " << OPENVPN_VERSION;
    os << ' ' << platform_name();
#   if defined(__amd64__) || defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
      os << " x86_64";
#   elif defined(__i386__) || defined(_M_IX86)
      os << " i386";
#   elif defined(__aarch64__) || defined(__arm64__)
      os << " arm64";
#   elif defined(__arm__) || defined(_M_ARM)
#     if defined(__ARM_ARCH_7S__) || defined(_ARM_ARCH_7S)
        os << " armv7s";
#     elif defined(__ARM_ARCH_7A__)
        os << " armv7a";
#     elif defined(__ARM_V7__) || defined(_ARM_ARCH_7)
        os << " armv7";
#     else
        os << " arm";
#     endif
#     if defined(__thumb2__)
	os << " thumb2";
#     elif defined(__thumb__) || defined(_M_ARMT)
        os << " thumb";
#     endif
#   endif

    os << ' ' << (sizeof(void *) * 8) << "-bit";
    return os.str();
  }
} // namespace openvpn

#endif // OPENVPN_COMMON_PLATFORM_STRING_H
