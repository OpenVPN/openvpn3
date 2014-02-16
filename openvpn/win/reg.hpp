//
//  reg.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// registry utilities for Windows

#ifndef OPENVPN_WIN_REG_H
#define OPENVPN_WIN_REG_H

#include <windows.h>
#include <boost/noncopyable.hpp>
#include <openvpn/common/types.hpp>

namespace openvpn {
  namespace Win {

    // HKEY wrapper
    class RegKey : boost::noncopyable {
    public:
      RegKey() : key(NULL) {}
      bool defined() const { return key != NULL; }
      HKEY* ref() { return &key; }
      HKEY operator()() { return key; }

      ~RegKey()
      {
	if (defined())
	  RegCloseKey(key);
      }
    private:
      HKEY key;
    };

  }
}

#endif
