#ifndef OPENVPN_COMMON_NUMBER_H
#define OPENVPN_COMMON_NUMBER_H

#include <string>
#include <limits>

#include <openvpn/common/types.hpp>

namespace openvpn {

  // note -- currently doesn't detect overflow
  template <typename T>
  T parse_number(const char *str)
  {
    if (!str[0])
      throw type_exception(); // empty string
    bool neg = false;
    size_t i = 0;
    if (std::numeric_limits<T>::min() < 0 && str[0] == '-')
      {
	neg = true;
	i = 1;
      }
    T ret = T(0);
    while (true)
      {
	const char c = str[i++];
	if (c >= '0' && c <= '9')
	  {
	    ret *= T(10);
	    ret += T(c - '0');
	  }
	else if (!c)
	  return neg ? -ret : ret;
	else
	  throw type_exception(); // non-digit
      }
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_NUMBER_H
