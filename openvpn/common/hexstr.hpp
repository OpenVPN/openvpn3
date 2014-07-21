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

// A collection of functions for rendering and parsing hexadecimal strings

#ifndef OPENVPN_COMMON_HEXSTR_H
#define OPENVPN_COMMON_HEXSTR_H

#include <string>

#include <openvpn/common/exception.hpp>

namespace openvpn {

  inline char render_hex_char(const int c)
  {
    if (c < 10)
      return '0' + c;
    else if (c < 16)
      return 'a' - 10 + c;
    else
      return '?';
  }

  inline int parse_hex_char (const char c)
  {
    if (c >= '0' && c <= '9')
      return c - '0';
    else if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    else
      return -1;
  }

  inline std::string render_hex(const unsigned char *data, size_t size)
  {
    std::string ret;
    ret.reserve(size*2+1);
    while (size--)
      {
	const unsigned char c = *data++;
	ret += render_hex_char(c >> 4);
	ret += render_hex_char(c & 0x0F);
      }
    return ret;
  }

  template <typename V>
  inline std::string render_hex(const V& data)
  {
    std::string ret;
    ret.reserve(data.size()*2+1);
    for (size_t i = 0; i < data.size(); ++i)
      {
	const unsigned char c = data[i];
	ret += render_hex_char(c >> 4);
	ret += render_hex_char(c & 0x0F);
      }
    return ret;
  }

  OPENVPN_SIMPLE_EXCEPTION(parse_hex_error);

  template <typename V>
  inline void parse_hex(V& dest, const std::string& str)
  {
    const int len = int(str.length());
    int i;
    for (i = 0; i <= len - 2; i += 2)
      {
	const int high = parse_hex_char(str[i]);
	const int low = parse_hex_char(str[i+1]);
	if (high == -1 || low == -1)
	  throw parse_hex_error();
	dest.push_back((high<<4) + low);
      }
    if (i != len)
      throw parse_hex_error(); // straggler char      
  }

  // note -- currently doesn't detect overflow
  template <typename T>
  inline T parse_hex_number(const char *str)
  {
    if (!str[0])
      throw parse_hex_error(); // empty string
    size_t i = 0;
    T ret = T(0);
    while (true)
      {
	const char c = str[i++];
	const int hd = parse_hex_char(c);
	if (hd >= 0)
	  {
	    ret *= T(16);
	    ret += T(hd);
	  }
	else if (!c)
	  return ret;
	else
	  throw parse_hex_error(); // non-hex-digit
      }
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_HEXSTR_H
