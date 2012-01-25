#ifndef OPENVPN_COMMON_SIGNAL_H
#define OPENVPN_COMMON_SIGNAL_H

#include <boost/asio.hpp>

#include <openvpn/common/platform.hpp>

namespace openvpn {

  class ASIOSignals
  {
  public:
    ASIOSignals(boost::asio::io_service& io_service)
      : signals_(io_service) {}

    enum {
      S_SIGINT  = (1<<0),
      S_SIGTERM = (1<<1),
      S_SIGQUIT = (1<<2),
#ifndef OPENVPN_PLATFORM_WIN
      S_SIGHUP  = (1<<3)
#endif
    };

    template <typename StopHandler>
    void register_signals(StopHandler stop_handler, unsigned int sigmask = (S_SIGINT|S_SIGTERM|S_SIGQUIT))
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
      signals_.cancel();
    }

    private:
      boost::asio::signal_set signals_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_SIGNAL_H
