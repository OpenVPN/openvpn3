#ifndef OPENVPN_APPLECRYPTO_UTIL_RAND_H
#define OPENVPN_APPLECRYPTO_UTIL_RAND_H

#include <Security/SecRandom.h>

#include <openvpn/random/randbase.hpp>

namespace openvpn {
  class RandomAppleCrypto : public RandomBase {
  public:
    virtual const char *name() const {
      return "SecRandom";
    }

    virtual void rand_bytes(unsigned char *buf, const size_t size)
    {
      if (SecRandomCopyBytes(kSecRandomDefault, size, buf) == -1)
	throw rand_error("SecRandom rand_bytes");
    }
  };
}

#endif
