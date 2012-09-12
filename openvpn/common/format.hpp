//
//  format.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_FORMAT_H
#define OPENVPN_COMMON_FORMAT_H

#include <string>
#include <sstream>

namespace openvpn {

  template <typename T>
  std::string to_string(const T& value)
  {
    std::ostringstream os;
    os << value;
    return os.str();
  }

} // namespace openvpn

#endif
