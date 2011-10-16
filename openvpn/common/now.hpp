#ifndef OPENVPN_COMMON_NOW_H
#define OPENVPN_COMMON_NOW_H

#include <openvpn/common/time.hpp>

namespace openvpn {

  volatile time::coarse::abs now = 0; /* GLOBAL */

  inline void update_now()
  {
    now = time::coarse::now();
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_NOW_H
