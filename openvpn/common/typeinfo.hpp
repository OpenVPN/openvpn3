//
//  typeinfo.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// useful constructions for template methods that want to parse or get
// information about particular types

#ifndef OPENVPN_COMMON_TYPEINFO_H
#define OPENVPN_COMMON_TYPEINFO_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/number.hpp>

#define OPENVPN_NUMBER_TYPE(T) \
  template <> \
  struct types<T> \
  { \
    static const char *name() { return #T; } \
    static T parse(const std::string& str) \
      { \
        return parse_number_str<T>(str); \
      } \
    static void parse(const std::string& str, T& ret) \
    { \
      ret = parse_number_str<T>(str); \
    } \
  }

namespace openvpn {
  OPENVPN_NUMBER_TYPE(int);
  OPENVPN_NUMBER_TYPE(unsigned int);
  OPENVPN_NUMBER_TYPE(short);
  OPENVPN_NUMBER_TYPE(unsigned short);
  OPENVPN_NUMBER_TYPE(long);
  OPENVPN_NUMBER_TYPE(unsigned long);

  template <>
  struct types<std::string>
  {
    static const char *name() { return "string"; }

    static std::string parse(const std::string& str)
    {
      return str;
    }

    static void parse(const std::string& str, std::string& ret)
    {
      ret = str;
    }
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_TYPEINFO_H
