#ifndef OPENVPN_RANDOM_RAND_H
#define OPENVPN_RANDOM_RAND_H

#include <openvpn/common/exception.hpp>
#include <openvpn/random/boostrand.hpp>

#include <openvpn/gencrypto/applecrypto.hpp>
#ifdef OPENVPN_APPLE_CRYPTO
#include <Security/SecRandom.h>
#else
#include <openssl/rand.h>
#endif

namespace openvpn {
  OPENVPN_SIMPLE_EXCEPTION(rand_error);

#ifdef OPENVPN_APPLE_CRYPTO
  inline void rand_bytes(unsigned char *buf, const size_t size)
  {
    if (SecRandomCopyBytes(kSecRandomDefault, size, buf) == -1)
      throw rand_error();
  }
#else
  inline void rand_bytes(unsigned char *buf, const size_t size)
  {
    if (!RAND_bytes(buf, size))
      throw rand_error();
  }
#endif

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
