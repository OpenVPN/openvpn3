#ifndef OPENVPN_GENCRYPTO_GENRAND_H
#define OPENVPN_GENCRYPTO_GENRAND_H

#include <openvpn/gencrypto/gencrypto.hpp>
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

} // namespace openvpn

#endif // OPENVPN_GENCRYPTO_GENRAND_H
