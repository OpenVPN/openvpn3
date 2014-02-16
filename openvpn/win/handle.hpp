//
//  handle.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// windows HANDLE utilities

#ifndef OPENVPN_WIN_HANDLE_H
#define OPENVPN_WIN_HANDLE_H

#include <windows.h>

namespace openvpn {
  namespace Win {
    namespace Handle {
      inline HANDLE undefined()
      {
	return INVALID_HANDLE_VALUE;
      }

      inline bool defined(HANDLE handle)
      {
	return handle != NULL && handle != INVALID_HANDLE_VALUE;
      }
    }
  }
}

#endif
