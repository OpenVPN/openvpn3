//
//  listener.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2018 OpenVPN Technologies, Inc.
//  All rights reserved.
//


#pragma once

#include <openvpn/common/rc.hpp>
#include <openvpn/acceptor/base.hpp>

namespace openvpn
{
  // generic structure implemented by the various proxies used by PGProxy
  struct ProxyListener : public Acceptor::ListenerBase
  {
    typedef RCPtr<ProxyListener> Ptr;

    virtual void start() = 0;
    virtual void stop() = 0;
  };
}
