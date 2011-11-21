#ifndef OPENVPN_COMMON_STRING_H
#define OPENVPN_COMMON_STRING_H

#include <cstring>

namespace openvpn {
  namespace string {
    inline int strcasecmp(const char *s1, const char *s2)
    {
      return ::strcasecmp(s1, s2);
    }
  } // namespace string
} // namespace openvpn

#endif // OPENVPN_COMMON_STRING_H
