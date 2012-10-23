//
//  reconnect_notify.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TRANSPORT_RECONNECT_NOTIFY_H
#define OPENVPN_TRANSPORT_RECONNECT_NOTIFY_H

namespace openvpn {
  class ReconnectNotify {
  public:
    // When a connection is close to timeout, the core will call this
    // method.  If it returns false, the core will disconnect with a
    // CONNECTION_TIMEOUT event.  If true, the core will enter a PAUSE
    // state.
    virtual bool pause_on_connection_timeout() = 0;
  };
}

#endif
