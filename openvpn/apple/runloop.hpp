//
//  runloop.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_APPLE_RUNLOOP_H
#define OPENVPN_APPLE_RUNLOOP_H

#include <openvpn/applecrypto/cf/cf.hpp>

namespace openvpn {
  namespace CF {
    OPENVPN_CF_WRAP(RunLoop, runloop_cast, CFRunLoopRef, CFRunLoopGetTypeID);
    OPENVPN_CF_WRAP(RunLoopSource, runloop_source_cast, CFRunLoopSourceRef, CFRunLoopSourceGetTypeID);
  }
}

#endif
