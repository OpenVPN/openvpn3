#ifndef OPENVPN_COMMON_STRING_H
#define OPENVPN_COMMON_STRING_H

#include <cstring>

#include <openvpn/common/types.hpp>

namespace openvpn {
  namespace string {
    inline int strcasecmp(const char *s1, const char *s2)
    {
      return ::strcasecmp(s1, s2);
    }

    /* Like strncpy but makes sure dest is always null terminated */
    inline void strncpynt (char *dest, const char *src, size_t maxlen)
    {
      strncpy (dest, src, maxlen);
      if (maxlen > 0)
	dest[maxlen - 1] = 0;
    }
  } // namespace string
} // namespace openvpn

#endif // OPENVPN_COMMON_STRING_H
