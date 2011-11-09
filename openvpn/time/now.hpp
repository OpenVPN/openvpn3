#ifndef OPENVPN_COMMON_NOW_H
#define OPENVPN_COMMON_NOW_H

#include <openvpn/time/time.hpp>

namespace openvpn {
  namespace time {

    Time now; /* GLOBAL */ // fixme should be volatile

  } // namespace time
} // namespace openvpn

#endif // OPENVPN_COMMON_NOW_H
