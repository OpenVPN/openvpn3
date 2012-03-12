#ifndef OPENVPN_OPENSSL_UTIL_RAND_H
#define OPENVPN_OPENSSL_UTIL_RAND_H

#include <openssl/rand.h>

#include <openvpn/common/rc.hpp>

namespace openvpn {
  class OpenSSLRandom : public RC<thread_unsafe_refcount> {
  public:
    OPENVPN_EXCEPTION(rand_error_openssl);

    typedef boost::intrusive_ptr<OpenSSLRandom> Ptr;

    const char *name() const {
      return "OpenSSLRandom";
    }

    void rand_bytes(unsigned char *buf, const size_t size)
    {
      if (!RAND_bytes(buf, size))
	throw rand_error_openssl("rand_bytes");
    }
  };
}

#endif
