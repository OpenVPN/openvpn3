#ifndef OPENVPN_OPENSSL_RAND_H
#define OPENVPN_OPENSSL_RAND_H

#include <openssl/rand.h>

#include <openvpn/common/exception.hpp>

namespace openvpn {
  OPENVPN_SIMPLE_EXCEPTION(rand_error);

  inline void rand_bytes(unsigned char *buf, const size_t size)
  {
    if (!RAND_bytes(buf, size))
      throw rand_error();
  }

} // namespace openvpn

#endif // OPENVPN_OPENSSL_RAND_H
