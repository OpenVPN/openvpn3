//
//  process.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_PROCESS_H
#define OPENVPN_COMMON_PROCESS_H

#include <string>
#include <stdlib.h> // defines system()

namespace openvpn {

  inline int system_cmd(const std::string& str)
  {
    return ::system(str.c_str());
  }

}
#endif // OPENVPN_COMMON_PROCESS_H
