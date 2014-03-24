//
//  cftimer.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_APPLECRYPTO_CF_CFTIMER_H
#define OPENVPN_APPLECRYPTO_CF_CFTIMER_H

#include <openvpn/applecrypto/cf/cf.hpp>

namespace openvpn {
  namespace CF {
    OPENVPN_CF_WRAP(Timer, timer_cast, CFRunLoopTimerRef, CFRunLoopTimerGetTypeID)
  }
}

#endif
