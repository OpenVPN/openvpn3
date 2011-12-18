#ifndef OPENVPN_COMMON_TYPES_H
#define OPENVPN_COMMON_TYPES_H

#include <cstddef> // defines size_t and NULL

#include <openvpn/common/exception.hpp>

namespace openvpn {

  typedef long long count_t;

  OPENVPN_SIMPLE_EXCEPTION(type_exception);

  template <typename T> struct types {};

} // namespace openvpn

#endif // OPENVPN_COMMON_TYPES_H
