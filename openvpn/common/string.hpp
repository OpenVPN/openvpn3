//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

#include <string>
#include <vector>
#include <cstring>
#include <cctype>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/size.hpp>

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

    // remove trailing \r or \n chars
    inline std::string trim_crlf_copy(std::string str)
    {
      trim_crlf(str);
      return str;
    }

    // return true if string ends with a newline
    inline bool ends_with_newline(const std::string& str)
    {
      const size_t len = str.length();
      return len > 0 && str[len-1] == '\n';
    }

    // return true if str of size len contains an embedded null
    inline bool embedded_null(const char *str, size_t len)
    {
      while (len--)
	if (!*str++)
	  return true;
      return false;
    }

    // return the length of a string, omitting trailing nulls
    inline size_t len_without_trailing_nulls(const char *str, size_t len)
    {
      while (len > 0 && str[len-1] == '\0')
	--len;
      return len;
    }

    // return true if string contains at least one newline
    inline bool is_multiline(const std::string& str)
    {
      return str.find_first_of('\n') != std::string::npos;
    }

    // Define a common interpretation of what constitutes a space character.
    // Return true if c is a space char.
    inline bool is_space(const char c)
    {
      return std::isspace(static_cast<unsigned char>(c)) != 0;
    }

    inline bool is_digit(const char c)
    {
      return std::isdigit(static_cast<unsigned char>(c)) != 0;
    }

    inline bool is_printable(const char c)
    {
      return std::isprint(static_cast<unsigned char>(c)) != 0;
    }

    inline bool is_printable(const unsigned char c)
    {
      return std::isprint(c) != 0;
    }

    // return true if str contains at least one space char
    inline bool contains_space(const std::string& str)
    {
      for (std::string::const_iterator i = str.begin(); i != str.end(); ++i)
	if (is_space(*i))
	  return true;
      return false;
    }

    // replace all spaces in string with rep
    inline std::string replace_spaces(const std::string& str, const char rep)
    {
      std::string ret;
      for (std::string::const_iterator i = str.begin(); i != str.end(); ++i)
	{
	  char c = *i;
	  if (is_space(c))
	    c = rep;
	  ret += c;
	}
      return ret;
    }

    // generate a string with spaces
    inline std::string spaces(int n)
    {
      std::string ret;
      ret.reserve(n);
      while (n-- > 0)
	ret += ' ';
      return ret;
    }

    // indent a multiline string
    inline std::string indent(const std::string& str, const int first, const int remaining)
    {
      std::string ret = spaces(first);
      for (auto &c : str)
	{
	  ret += c;
	  if (c == '\n')
	    ret += spaces(remaining);
	}
      return ret;
    }

    // return true if str is empty or contains only space chars
    inline bool is_empty(const std::string& str)
    {
      for (const auto& c : str)
	if (!is_space(c))
	  return false;
      return true;
    }

    // return true if str is empty or contains only space chars
    inline bool is_empty(const char *str)
    {
      if (!str)
	return true;
      char c;
      while ((c = *str++) != '\0')
	if (!is_space(c))
	  return false;
      return true;
    }

    // convert \n to \r\n
    inline std::string unix2dos(const std::string& str)
    {
      std::string ret;
      bool last_char_was_cr = false;

      ret.reserve(str.length() + str.length() / 8);
      for (std::string::const_iterator i = str.begin(); i != str.end(); ++i)
	{
	  const char c = *i;
	  if (c == '\n' && !last_char_was_cr)
	    ret += '\r';
	  ret += c;
	  last_char_was_cr = (c == '\r');
	}
      return ret;
    }

    // Split a string on sep delimiter.  The size of the
    // returned string list will be at most maxsplit + 1.
    inline std::vector<std::string> split(const std::string& str,
					  const char sep,
					  const int maxsplit = -1)
    {
      std::vector<std::string> ret;
      int nterms = 0;
      std::string term;

      for (auto &c : str)
	{
	  if (c == sep && (maxsplit < 0 || nterms < maxsplit))
	    {
	      ret.push_back(std::move(term));
	      ++nterms;
	      term = "";
	    }
	  else
	    term += c;
	}
      ret.push_back(std::move(term));
      return ret;
    }

    inline bool starts_with(const std::string& str, const std::string& prefix)
    {
      const size_t len = str.length();
      const size_t plen = prefix.length();
      if (plen <= len)
	return std::memcmp(str.c_str(), prefix.c_str(), plen) == 0;
      else
	return false;
    }

    inline bool starts_with(const std::string& str, const char *prefix)
    {
      const size_t len = str.length();
      const size_t plen = std::strlen(prefix);
      if (plen <= len)
	return std::memcmp(str.c_str(), prefix, plen) == 0;
      else
	return false;
    }

    inline bool ends_with(const std::string& str, const std::string& suffix)
    {
      const size_t len = str.length();
      const size_t slen = suffix.length();
      if (slen <= len)
	return std::memcmp(str.c_str() + (len-slen), suffix.c_str(), slen) == 0;
      else
	return false;
    }

    inline bool ends_with(const std::string& str, const char *suffix)
    {
      const size_t len = str.length();
      const size_t slen = std::strlen(suffix);
      if (slen <= len)
	return std::memcmp(str.c_str() + (len-slen), suffix, slen) == 0;
      else
	return false;
    }

    inline std::string trim_left_copy(const std::string& str)
    {
      for (size_t i = 0; i < str.length(); ++i)
	{
	  if (!is_space(str[i]))
	    return str.substr(i);
	}
      return std::string();
    }

    inline std::string trim_copy(const std::string& str)
    {
      for (size_t i = 0; i < str.length(); ++i)
	{
	  if (!is_space(str[i]))
	    {
	      size_t last_nonspace = i;
	      for (size_t j = i + 1; j < str.length(); ++j)
		{
		  if (!is_space(str[j]))
		    last_nonspace = j;
		}
	      return str.substr(i, last_nonspace - i + 1);
	    }
	}
      return std::string();
    }

    inline std::string to_upper_copy(const std::string& str)
    {
      std::string ret;
      ret.reserve(str.length()+1);
      for (const auto &c : str)
	ret.push_back(std::toupper(static_cast<unsigned char>(c)));
      return ret;
    }

    inline std::string to_lower_copy(const std::string& str)
    {
      std::string ret;
      ret.reserve(str.length()+1);
      for (const auto &c : str)
	ret.push_back(std::tolower(static_cast<unsigned char>(c)));
      return ret;
    }

    inline void trim(std::string& str)
    {
      str = trim_copy(str);
    }

    inline void trim_left(std::string& str)
    {
      str = trim_left_copy(str);
    }

    inline void to_lower(std::string& str)
    {
      str = to_lower_copy(str);
    }

    inline void to_upper(std::string& str)
    {
      str = to_upper_copy(str);
    }

    // Replace any subsequence of consecutive space chars containing
    // at least one newline with a single newline char.  If string
    // is non-empty and doesn't include a trailing newline, add one.
    inline std::string remove_blanks(const std::string& str)
    {
      std::string ret;
      ret.reserve(str.length()+1);

      std::string spaces;
      bool in_space = false;
      bool has_nl = false;

      for (auto &c : str)
	{
	  const bool s = is_space(c);
	reprocess:
	  if (in_space)
	    {
	      if (s)
		{
		  if (c == '\n')
		    has_nl = true;
		  spaces += c;
		}
	      else
		{
		  if (has_nl)
		    ret += '\n';
		  else
		    ret += spaces;
		  in_space = false;
		  has_nl = false;
		  spaces.clear();
		  goto reprocess;
		}
	    }
	  else
	    {
	      if (s)
		{
		  in_space = true;
		  goto reprocess;
		}
	      else
		ret += c;
	    }
	}
      if (!ret.empty() && !ends_with_newline(ret))
	ret += '\n';
      return ret;
    }

  } // namespace string

} // namespace openvpn

#endif // OPENVPN_COMMON_STRING_H
