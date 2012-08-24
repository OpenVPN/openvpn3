//
//  platform_name.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_PLATFORM_NAME_H
#define OPENVPN_COMMON_PLATFORM_NAME_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/platform.hpp>

namespace openvpn {

  inline const char *platform_name()
  {
#if defined(OPENVPN_PLATFORM_WIN)
    return "win";
#elif defined(OPENVPN_PLATFORM_MAC)
    return "mac";
#elif defined(OPENVPN_PLATFORM_IPHONE)
    return "ios";
#elif defined(OPENVPN_PLATFORM_IPHONE_SIMULATOR)
    return "iosim";
#elif defined(OPENVPN_PLATFORM_ANDROID)
    return "android";
#elif defined(OPENVPN_PLATFORM_LINUX)
    return "linux";
#else
    return NULL;
#endif
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_PLATFORM_NAME_H
