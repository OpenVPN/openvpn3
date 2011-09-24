#ifndef OPENVPN_COMMON_SIGNAL_H
#define OPENVPN_COMMON_SIGNAL_H

#include <boost/asio.hpp>

namespace openvpn {

  class ASIOSignals
  {
  public:
    explicit ASIOSignals(boost::asio::io_service& io_service)
      : signals_(io_service) {}

    template <typename StopHandler>
    void register_signals(StopHandler stop_handler)
    {
      signals_.add(SIGINT);
      signals_.add(SIGTERM);
#if defined(SIGQUIT)
      signals_.add(SIGQUIT);
#endif // defined(SIGQUIT)
      signals_.async_wait(stop_handler);
    }

    private:
      boost::asio::signal_set signals_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_SIGNAL_H
