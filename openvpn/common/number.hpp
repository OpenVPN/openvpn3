//
//  number.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_NUMBER_H
#define OPENVPN_COMMON_NUMBER_H

#include <string>
#include <limits>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {

  OPENVPN_SIMPLE_EXCEPTION(number_parse_exception);

  // Parse the number of type T in str, returning
  // value in retval.  Returns true on success.
  // Note -- currently doesn't detect overflow.
  template <typename T>
  inline bool parse_number(const char *str, T& retval)
  {
    if (!str[0])
      return false; // empty string
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
	  {
	    retval = neg ? -ret : ret;
	    return true;
	  }
	else
	  return false; // non-digit
      }
  }

  // like parse_number above, but throw exception on error
  template <typename T>
  inline T parse_number(const char *str)
  {
    T ret;
    if (parse_number<T>(str, ret))
      return ret;
    else
      throw number_parse_exception();
  }

  // like parse_number above, but accepts std::string
  template <typename T>
  inline T parse_number_str(const std::string& str)
  {
    return parse_number<T>(str.c_str());
  }

  inline bool is_number(const char *str)
  {
    char c;
    bool found_digit = false;
    while ((c = *str++))
      {
	if (c >= '0' && c <= '9')
	  found_digit = true;
	else
	  return false;
      }
    return found_digit;
  }

  template <typename T>
  inline bool validate_number(const std::string& numstr,
			      const size_t max_len,
			      const T minimum,
			      const T maximum,
			      T* value_return = NULL)
  {
    if (numstr.length() <= max_len)
      {
	T value;
	if (parse_number<T>(numstr.c_str(), value))
	  {
	    if (value >= minimum && value <= maximum)
	      {
		if (value_return)
		  *value_return = value;
		return true;
	      }
	  }
      }
    return false;
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_NUMBER_H
