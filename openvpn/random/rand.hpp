#ifndef OPENVPN_RANDOM_RAND_H
#define OPENVPN_RANDOM_RAND_H

#include <openvpn/common/exception.hpp>
#include <openvpn/random/boostrand.hpp>
#include <openvpn/random/randbase.hpp>

namespace openvpn {

  template <typename T>
  inline T rand_type(RandomBase& rng)
  {
    T ret;
    rng.rand_bytes((unsigned char *)&ret, sizeof(ret));
    return ret;
  }

  class RandomInt : public RandomIntBase
  {
  public:
    RandomInt(RandomBase& rng) : RandomIntBase(rand_type<unsigned int>(rng)) {}
  };

} // namespace openvpn

#endif // OPENVPN_RANDOM_RAND_H
