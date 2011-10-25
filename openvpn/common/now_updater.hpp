#ifndef OPENVPN_COMMON_NOW_UPDATER_H
#define OPENVPN_COMMON_NOW_UPDATER_H

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/asio.hpp>

#include <openvpn/common/now.hpp>
#include <openvpn/common/dispatch.hpp>

namespace openvpn {

  class NowUpdater
  {
  public:
    NowUpdater(boost::asio::io_service& io_service)
      : timer_(io_service),
	epoch_(time::fine::gregorian::date(1970,1,1))
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
      const time::fine::abs local_now = time::fine::now();	
      const time::fine::delta since_epoch = local_now - epoch_;
      const time::fine::delta::fractional_seconds_type fs = since_epoch.fractional_seconds();
      const time::fine::delta next_second(0, 0, 0, since_epoch.ticks_per_second() - fs);
      now = since_epoch.total_seconds();
      timer_.expires_at(local_now + next_second);
      timer_.async_wait(openvpn::asio_dispatch_timer(&NowUpdater::timer_callback, this));
    }

    boost::asio::deadline_timer timer_;
    const time::fine::abs epoch_;
};

} // namespace openvpn

#endif //OPENVPN_COMMON_NOW_UPDATER_H
