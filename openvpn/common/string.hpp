//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

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

    // return true if str of size len contains an embedded null
    inline bool embedded_null(const char *str, size_t len)
    {
      while (len--)
	if (!*str++)
	  return true;
      return false;
    }

    // Define a common interpretation of what constitutes a space character.
    // Return true if c is a space char.
    inline bool is_space(char c)
    {
      return (c == ' ' ||
	      c == '\t' ||
	      c == '\n' ||
	      c == '\r');
    }

    // return true if str contains at least one space char
    inline bool contains_space(const std::string& str)
    {
      for (std::string::const_iterator i = str.begin(); i != str.end(); ++i)
	if (is_space(*i))
	  return true;
      return false;
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
