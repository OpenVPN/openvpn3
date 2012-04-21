#ifndef OPENVPN_COMMON_STRING_H
#define OPENVPN_COMMON_STRING_H

#include <openvpn/common/platform.hpp>

#include <string>
#include <cstring>

#include <openvpn/common/types.hpp>

namespace openvpn {
  namespace string {
    inline int strcasecmp(const char *s1, const char *s2)
    {
#ifdef OPENVPN_PLATFORM_WIN
      return ::_stricmp(s1, s2);
#else
      return ::strcasecmp(s1, s2);
#endif
    }

    /* Like strncpy but makes sure dest is always null terminated */
    inline void strncpynt (char *dest, const char *src, size_t maxlen)
    {
      strncpy (dest, src, maxlen);
      if (maxlen > 0)
	dest[maxlen - 1] = 0;
    }

    inline bool is_true(const std::string& str)
    {
      return str == "1" || !strcasecmp(str.c_str(), "true");
    }
  } // namespace string
} // namespace openvpn

#endif // OPENVPN_COMMON_STRING_H
