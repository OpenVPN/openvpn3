//
//  clilife.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_CLIENT_CLILIFE_H
#define OPENVPN_CLIENT_CLILIFE_H

#include <string>

#include <openvpn/common/rc.hpp>

namespace openvpn {
    // Base class for managing connection lifecycle notifications,
    // such as sleep, wakeup, network-unavailable, network-available.
    class ClientLifeCycle : public RC<thread_unsafe_refcount> {
    public:
      struct NotifyCallback {
	virtual void cln_stop() = 0;
	virtual void cln_pause(const std::string& reason) = 0;
	virtual void cln_resume() = 0;
	virtual void cln_reconnect(int seconds) = 0;
      };

      typedef boost::intrusive_ptr<ClientLifeCycle> Ptr;

      virtual bool network_available() = 0;

      virtual void start(NotifyCallback*) = 0;
      virtual void stop() = 0;
    };
}

#endif
