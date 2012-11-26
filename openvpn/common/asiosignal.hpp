//
//  asiosignal.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// A simple class that allows an arbitrary set of posix signals to be
// associated with an Asio handler.

#ifndef OPENVPN_COMMON_ASIOSIGNAL_H
#define OPENVPN_COMMON_ASIOSIGNAL_H

#include <boost/asio.hpp>

#include <openvpn/common/platform.hpp>
#include <openvpn/common/rc.hpp>

namespace openvpn {

  class ASIOSignals : public RC<thread_safe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<ASIOSignals> Ptr;

    ASIOSignals(boost::asio::io_service& io_service)
      : halt(false), signals_(io_service) {}

    enum {
      S_SIGINT  = (1<<0),
      S_SIGTERM = (1<<1),
      S_SIGQUIT = (1<<2),
#ifndef OPENVPN_PLATFORM_WIN
      S_SIGHUP  = (1<<3)
#endif
    };

    template <typename SignalHandler>
    void register_signals(SignalHandler stop_handler, unsigned int sigmask = (S_SIGINT|S_SIGTERM|S_SIGQUIT))
    {
      if (sigmask & S_SIGINT)
	signals_.add(SIGINT);
      if (sigmask & S_SIGTERM)
	signals_.add(SIGTERM);
#if defined(SIGQUIT)
      if (sigmask & S_SIGQUIT)
	signals_.add(SIGQUIT);
#endif // defined(SIGQUIT)
#ifndef OPENVPN_PLATFORM_WIN
      if (sigmask & S_SIGHUP)
	signals_.add(SIGHUP);
#endif
      signals_.async_wait(stop_handler);
    }

    void cancel()
    {
      if (!halt)
	{
	  halt = true;
	  signals_.cancel();
	}
    }

  private:
    bool halt;
    boost::asio::signal_set signals_;
  };

}

#endif
