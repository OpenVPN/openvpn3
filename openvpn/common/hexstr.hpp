#ifndef OPENVPN_COMMON_HEXSTR_H
#define OPENVPN_COMMON_HEXSTR_H

#include <string>
#include <vector>

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

  inline std::string render_hex(const std::vector<unsigned char>& data)
  {
    std::string ret;
    ret.reserve(data.size()*2+1);
    for (std::vector<unsigned char>::const_iterator i = data.begin(); i != data.end(); i++)
      {
	const unsigned char c = *i;
	ret += render_hex_char(c >> 4);
	ret += render_hex_char(c & 0x0F);
      }
    return ret;
  }

  OPENVPN_SIMPLE_EXCEPTION(parse_hex_error);

  inline void parse_hex(std::vector<unsigned char>& dest, std::string& str)
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

  inline std::vector<unsigned char> parse_hex(std::string& str)
  {
    std::vector<unsigned char> ret;
    parse_hex(ret, str);
    return ret;
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_HEXSTR_H
