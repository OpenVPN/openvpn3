#ifndef OPENVPN_RANDOM_RAND_H
#define OPENVPN_RANDOM_RAND_H

#include <openvpn/common/exception.hpp>
#include <openvpn/random/boostrand.hpp>
#include <openvpn/gencrypto/genrand.hpp>

namespace openvpn {

  template <typename T>
  inline T rand_type()
  {
    T ret;
    rand_bytes((unsigned char *)&ret, sizeof(ret));
    return ret;
  }

  class RandomInt : public RandomIntBase
  {
  public:
    RandomInt() : RandomIntBase(rand_type<unsigned int>()) {}
  };

} // namespace openvpn

#endif // OPENVPN_RANDOM_RAND_H
