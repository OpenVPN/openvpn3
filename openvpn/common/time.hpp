#ifndef OPENVPN_COMMON_TIME_H
#define OPENVPN_COMMON_TIME_H

#include <ctime>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/asio/time_traits.hpp>

namespace openvpn {
  namespace time {
    namespace fine {
      typedef boost::posix_time::ptime abs;            // high-res absolute time
      typedef boost::posix_time::time_duration delta;  // high-res relative time
      namespace gregorian = boost::gregorian;

      static inline abs now() // high-res current time
      {
	return boost::asio::time_traits<boost::posix_time::ptime>::now();
      }
    }
    namespace coarse {
      typedef ::time_t abs;   // low-res absolute time
      typedef ::time_t delta; // low-res relative time

      static inline abs now() // low-res current time
      {
	return ::time(0);
      }
    }
  }
} // namespace openvpn

#endif // OPENVPN_COMMON_TIME_H
