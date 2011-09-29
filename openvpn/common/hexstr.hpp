#ifndef OPENVPN_COMMON_HEXSTR_H
#define OPENVPN_COMMON_HEXSTR_H

#include <string>

namespace openvpn {

  char hexchar(const int c)
  {
    if (c < 10)
      return '0' + c;
    else if (c < 16)
      return 'a' - 10 + c;
    else
      return '?';
  }

  std::string hexstr(const unsigned char *data, size_t size)
  {
    std::string ret;
    ret.reserve(size*2+1);
    while (size--)
      {
	const unsigned char c = *data++;
	ret += hexchar(c >> 4);
	ret += hexchar(c & 0x0F);
      }
    return ret;
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_HEXSTR_H
