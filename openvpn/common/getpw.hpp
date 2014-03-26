//
//  getpw.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_GETPW_H
#define OPENVPN_COMMON_GETPW_H

#if !defined(OPENVPN_PLATFORM_WIN)
#include <pwd.h>
#include <unistd.h>
#endif

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/platform.hpp>

namespace openvpn {
  std::string get_password(const char *prompt)
  {
#if !defined(OPENVPN_PLATFORM_WIN)
    char *ret = getpass(prompt);
    return ret;
#else
    throw Exception("get_password not implemented yet for Windows");
#endif
  }
}

#endif
