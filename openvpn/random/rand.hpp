#ifndef OPENVPN_RANDOM_RAND_H
#define OPENVPN_RANDOM_RAND_H

#include <openssl/rand.h>

#include <openvpn/common/exception.hpp>
#include <openvpn/random/boostrand.hpp>

namespace openvpn {
  OPENVPN_SIMPLE_EXCEPTION(rand_error);

  inline void rand_bytes(unsigned char *buf, const size_t size)
  {
    if (!RAND_bytes(buf, size))
      throw rand_error();
  }

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
