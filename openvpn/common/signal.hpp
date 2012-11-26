//
//  signal.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_SIGNAL_H
#define OPENVPN_COMMON_SIGNAL_H

#include <signal.h>

#include <openvpn/common/exception.hpp>

namespace openvpn {
  class Signal
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(signal_error);

    typedef void (*handler_t)(int signum);

    enum {
      F_SIGINT  = (1<<0),
      F_SIGTERM = (1<<1),
      F_SIGHUP  = (1<<2),
    };

    Signal(const handler_t handler, const unsigned int flags)
    {
      struct sigaction sa;
      sa.sa_handler = handler;
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = SA_RESTART; // restart functions if interrupted by handler
      sigconf(sa, flags_ = flags);
    }

    ~Signal()
    {
      struct sigaction sa;
      sa.sa_handler = SIG_DFL;
      sigemptyset(&sa.sa_mask);
      sa.sa_flags = 0;
      sigconf(sa, flags_);
    }

  private:
    static void sigconf(struct sigaction& sa, const unsigned int flags)
    {
      if (flags & F_SIGINT)
	sigact(sa, SIGINT);
      if (flags & F_SIGTERM)
	sigact(sa, SIGTERM);
      if (flags & F_SIGHUP)
	sigact(sa, SIGHUP);
    }

    static void sigact(struct sigaction& sa, const int sig)
    {
      if (sigaction(sig, &sa, NULL) == -1)
	throw signal_error();
    }

    unsigned int flags_;
  };
}
#endif
