#ifndef OPENVPN_COMMON_SIGNAL_H
#define OPENVPN_COMMON_SIGNAL_H

#include <boost/asio.hpp>

namespace openvpn {

  class ASIOSignals
  {
  public:
    explicit ASIOSignals(boost::asio::io_service& io_service)
      : signals_(io_service) {}

    enum {
      S_SIGINT  = (1<<0),
      S_SIGTERM = (1<<1),
      S_SIGQUIT = (1<<2),
      S_SIGHUP  = (1<<3)
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
      if (sigmask & S_SIGHUP)
	signals_.add(SIGHUP);
      signals_.async_wait(stop_handler);
    }

    private:
      boost::asio::signal_set signals_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_SIGNAL_H
