//
//  port.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_PORT_H
#define OPENVPN_COMMON_PORT_H

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn {

  inline void validate_port(const std::string& port, const std::string& title, unsigned int *value = NULL)
  {
    if (!parse_number_validate<unsigned int>(port, 5, 1, 65535, value))
      OPENVPN_THROW(option_error, "bad " << title << " number: " << port);
  }

} // namespace openvpn

#endif
