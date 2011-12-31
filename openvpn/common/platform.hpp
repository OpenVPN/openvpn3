#ifndef OPENVPN_COMMON_PLATFORM_H
#define OPENVPN_COMMON_PLATFORM_H

#include <openvpn/common/types.hpp>

#if defined(__linux__)
#define OPENVPN_PLATFORM_LINUX
#elif defined(__APPLE__)
#define OPENVPN_PLATFORM_APPLE
#elif defined(_WIN32)
#define OPENVPN_PLATFORM_WIN
#endif

namespace openvpn {

  inline const char *platform_name()
  {
#if defined(OPENVPN_PLATFORM_LINUX)
    return "linux";
#elif defined(OPENVPN_PLATFORM_APPLE)
    return "mac";
#elif defined(OPENVPN_PLATFORM_WIN)
    return "win";
#else
    return NULL;
#endif
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_PLATFORM_H
