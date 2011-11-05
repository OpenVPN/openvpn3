#ifndef OPENVPN_COMMON_NOW_UPDATER_H
#define OPENVPN_COMMON_NOW_UPDATER_H

#include <openvpn/common/asiotimer.hpp>
#include <openvpn/time/now.hpp>
#include <openvpn/common/dispatch.hpp>

namespace openvpn {

  class NowUpdater
  {
  public:
    NowUpdater(boost::asio::io_service& io_service)
      : timer_(io_service)
    {
      update();
    }

  void stop()
  {
    timer_.cancel();
  }

  private:
    void timer_callback(const boost::system::error_code& e)
    {
      if (!e)
	update();
    }

    void update()
    {
      const Time local_now = Time::now();
      const Time::type fs = local_now.fractional_binary_ms();
      const Time::Duration next_second = Time::Duration::binary_ms(Time::prec - fs);
      now = local_now.seconds_since_epoch();
      //std::cout << now << std::endl;
      timer_.expires_at(local_now + next_second);
      timer_.async_wait(asio_dispatch_timer(&NowUpdater::timer_callback, this));
    }

    AsioTimer timer_;
};

} // namespace openvpn

#endif //OPENVPN_COMMON_NOW_UPDATER_H
