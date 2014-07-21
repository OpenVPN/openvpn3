//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

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
