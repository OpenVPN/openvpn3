#ifndef OPENVPN_GENCRYPTO_GENRAND_H
#define OPENVPN_GENCRYPTO_GENRAND_H

#if defined(USE_OPENSSL)
#include <openssl/rand.h>
#elif defined(USE_APPLE_SSL)
#include <Security/SecRandom.h>
#else
#error no library available to provide entropy for rand_bytes
#endif

namespace openvpn {
  OPENVPN_SIMPLE_EXCEPTION(rand_error);

  inline void rand_bytes(unsigned char *buf, const size_t size)
  {
#if defined(USE_OPENSSL)
    if (!RAND_bytes(buf, size))
      throw rand_error();
#elif defined(USE_APPLE_SSL)
    if (SecRandomCopyBytes(kSecRandomDefault, size, buf) == -1)
      throw rand_error();
#endif
  }

} // namespace openvpn

#endif // OPENVPN_GENCRYPTO_GENRAND_H
