#ifndef OPENVPN_COMMON_NOW_H
#define OPENVPN_COMMON_NOW_H

#include <openvpn/common/time.hpp>

namespace openvpn {

  volatile Time::base_type now = 0; /* GLOBAL */

} // namespace openvpn

#endif // OPENVPN_COMMON_NOW_H
