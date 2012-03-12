#ifndef OPENVPN_APPLECRYPTO_UTIL_RAND_H
#define OPENVPN_APPLECRYPTO_UTIL_RAND_H

#include <Security/SecRandom.h>

#include <openvpn/common/rc.hpp>

namespace openvpn {
  class AppleRandom : public RC<thread_unsafe_refcount> {
  public:
    OPENVPN_EXCEPTION(rand_error_apple);

    typedef boost::intrusive_ptr<AppleRandom> Ptr;

    const char *name() const {
      return "AppleRandom";
    }

    void rand_bytes(unsigned char *buf, const size_t size)
    {
      if (SecRandomCopyBytes(kSecRandomDefault, size, buf) == -1)
	throw rand_error_apple("rand_bytes");
    }
  };
}

#endif
