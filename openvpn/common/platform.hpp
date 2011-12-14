#ifndef OPENVPN_COMMON_PLATFORM_H
#define OPENVPN_COMMON_PLATFORM_H

#include <openvpn/common/types.hpp>

namespace openvpn {

  inline const char *platform_name()
  {
#if defined(__linux__)
    return "linux";
#elif defined(__APPLE__)
    return "mac";
#elif defined(_WIN32)
    return "win";
#else
    return NULL;
#endif
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_PLATFORM_H
