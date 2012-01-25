#ifndef OPENVPN_COMMON_TYPES_H
#define OPENVPN_COMMON_TYPES_H

#include <cstddef> // defines size_t and NULL

#include <openvpn/common/exception.hpp>
#include <openvpn/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_WIN
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#else
#include <unistd.h> // get ssize_t
#endif

namespace openvpn {

  typedef long long count_t;

  OPENVPN_SIMPLE_EXCEPTION(type_exception);

  template <typename T> struct types {};

} // namespace openvpn

#endif // OPENVPN_COMMON_TYPES_H
