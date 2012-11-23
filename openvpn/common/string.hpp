//
//  string.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// General purpose string-manipulation functions.

#ifndef OPENVPN_COMMON_STRING_H
#define OPENVPN_COMMON_STRING_H

#include <openvpn/common/platform.hpp>
#include <openvpn/common/rc.hpp>

#include <string>
#include <cstring>

#include <openvpn/common/types.hpp>

namespace openvpn {
  namespace string {
    // case insensitive compare functions

    inline int strcasecmp(const char *s1, const char *s2)
    {
#ifdef OPENVPN_PLATFORM_WIN
      return ::_stricmp(s1, s2);
#else
      return ::strcasecmp(s1, s2);
#endif
    }

    inline int strcasecmp(const std::string& s1, const char *s2)
    {
      return strcasecmp(s1.c_str(), s2);
    }

    inline int strcasecmp(const char *s1, const std::string& s2)
    {
      return strcasecmp(s1, s2.c_str());
    }

    inline int strcasecmp(const std::string& s1, const std::string& s2)
    {
      return strcasecmp(s1.c_str(), s2.c_str());
    }

    // Like strncpy but makes sure dest is always null terminated
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

    // make sure that string ends with char c, if not append it
    inline std::string add_trailing(const std::string& str, const char c)
    {
      const size_t len = str.length();
      if (len > 0 && str[len-1] == c)
	return str;
      else
	return str + c;
    }

    // make sure that string ends with char c, if not append it
    inline void add_trailing_in_place(std::string& str, const char c)
    {
      const size_t len = str.length();
      if (!(len > 0 && str[len-1] == c))
	str += c;
    }

    // remove trailing \r or \n chars
    inline void trim_crlf(std::string& str)
    {
      static const char crlf[] = "\r\n";
      const size_t pos = str.find_last_not_of(crlf);
      if (pos == std::string::npos)
	str = "";
      else
	{
	  const size_t p = pos + 1;
	  if (p < str.length())
	    str = str.substr(0, p);
	}
    }
  } // namespace string

  // Reference-counted string
  struct String : public std::string, RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<String> Ptr;

    String() {}
    explicit String(const std::string& str) : std::string(str) {}
    explicit String(const std::string& str, size_t pos, size_t n = std::string::npos) : std::string(str, pos, npos) {}
    explicit String(const char *s, size_t n) : std::string(s, n) {}
    explicit String(const char *s) : std::string(s) {}
    explicit String(size_t n, char c) : std::string(n, c) {}
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_STRING_H
