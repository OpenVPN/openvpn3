#ifndef OPENVPN_COMMON_NOW_H
#define OPENVPN_COMMON_NOW_H

#include <ctime>

namespace openvpn {

  typedef ::time_t time_t;
  volatile time_t now = 0; /* GLOBAL */

  inline void update_now()
  {
    now = time(NULL);
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_NOW_H
