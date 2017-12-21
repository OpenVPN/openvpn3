//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Inc.
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
#include <iomanip>
#include <sstream>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>

namespace openvpn {

  inline char render_hex_char(const int c, const bool caps=false)
  {
    if (c < 10)
      return '0' + c;
    else if (c < 16)
      return (caps ? 'A' : 'a') - 10 + c;
    else
      return '?';
  }

  inline int parse_hex_char(const char c)
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

  class RenderHexByte
  {
  public:
    RenderHexByte(const unsigned char byte, const bool caps=false)
    {
      c[0] = render_hex_char(byte >> 4, caps);
      c[1] = render_hex_char(byte & 0x0F, caps);
    }

    char char1() const { return c[0]; }
    char char2() const { return c[1]; }

    const char *str2() const { return c; } // Note: length=2, NOT null terminated

  private:
    char c[2];
  };

  inline std::string render_hex(const unsigned char *data, size_t size, const bool caps=false)
  {
    if (!data)
      return "NULL";
    std::string ret;
    ret.reserve(size*2+1);
    while (size--)
      {
	const RenderHexByte b(*data++, caps);
	ret += b.char1();
	ret += b.char2();
      }
    return ret;
  }

  inline std::string render_hex(const void *data, const size_t size, const bool caps=false)
  {
    return render_hex((const unsigned char *)data, size, caps);
  }

  inline std::string render_hex_sep(const unsigned char *data, size_t size, const char sep, const bool caps=false)
  {
    if (!data)
      return "NULL";
    std::string ret;
    ret.reserve(size*3);
    bool prsep = false;
    while (size--)
      {
	if (prsep)
	  ret += sep;
	const RenderHexByte b(*data++, caps);
	ret += b.char1();
	ret += b.char2();
	prsep = true;
      }
    return ret;
  }

  inline std::string render_hex_sep(const void *data, const size_t size, const char sep, const bool caps=false)
  {
    return render_hex_sep((const unsigned char *)data, size, sep, caps);
  }

  template <typename V>
  inline std::string render_hex_generic(const V& data, const bool caps=false)
  {
    std::string ret;
    ret.reserve(data.size()*2+1);
    for (size_t i = 0; i < data.size(); ++i)
      {
	const RenderHexByte b(data[i], caps);
	ret += b.char1();
	ret += b.char2();
      }
    return ret;
  }

  inline std::string dump_hex(const unsigned char *data, size_t size)
  {
    if (!data)
      return "NULL\n";
    const unsigned int mask = 0x0F; // N bytes per line - 1
    std::ostringstream os;
    os << std::hex;
    std::string chars;
    size_t i;
    for (i = 0; i < size; ++i)
      {
	if (!(i & mask))
	  {
	    if (i)
	      {
		os << "  " << chars << std::endl;
		chars.clear();
	      }
	    os << std::setfill(' ') << std::setw(8) << i << ":";
	  }
	const unsigned char c = data[i];
	os << ' ' << std::setfill('0') << std::setw(2) << (unsigned int)c;
	if (string::is_printable(c))
	  chars += c;
	else
	  chars += '.';
      }
    if (i)
      os << string::spaces(2 + (((i-1) & mask) ^ mask) * 3) << chars << std::endl;
    return os.str();
  }

  inline std::string dump_hex(const std::string& str)
  {
    return dump_hex((const unsigned char *)str.c_str(), str.length());
  }

  template <typename V>
  inline std::string dump_hex(const V& data)
  {
    return dump_hex(data.c_data(), data.size());
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
  inline bool parse_hex_number(const char *str, T& retval)
  {
    if (!str[0])
      return false; // empty string
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
	  {
	    retval = ret;
	    return true;
	  }
	else
	  return false; // non-hex-digit
      }
  }

  template <typename T>
  inline bool parse_hex_number(const std::string& str, T& retval)
  {
    return parse_hex_number(str.c_str(), retval);
  }

  template <typename T>
  inline T parse_hex_number(const std::string& str)
  {
    T ret;
    if (!parse_hex_number<T>(str.c_str(), ret))
      throw parse_hex_error();
    return ret;
  }

  template <typename T>
  std::string render_hex_number(T value, const bool caps=false)
  {
    unsigned char buf[sizeof(T)];
    for (size_t i = sizeof(T); i --> 0 ;)
      {
	buf[i] = value & 0xFF;
	value >>= 8;
      }
    return render_hex(buf, sizeof(T), caps);
  }

  std::string render_hex_number(unsigned char uc, const bool caps=false)
  {
    RenderHexByte b(uc, caps);
    return std::string(b.str2(), 2);
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_HEXSTR_H
