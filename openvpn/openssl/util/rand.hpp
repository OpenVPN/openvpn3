#ifndef OPENVPN_OPENSSL_UTIL_RAND_H
#define OPENVPN_OPENSSL_UTIL_RAND_H

#include <openssl/rand.h>

#include <openvpn/random/randbase.hpp>

namespace openvpn {
  class RandomOpenSSL : public RandomBase {
  public:
    virtual const char *name() const {
      return "OpenSSL";
    }

    virtual void rand_bytes(unsigned char *buf, const size_t size)
    {
      if (!RAND_bytes(buf, size))
	throw rand_error("OpenSSL rand_bytes");
    }
  };
}

#endif
