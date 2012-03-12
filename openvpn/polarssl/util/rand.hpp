#ifndef OPENVPN_POLARSSL_UTIL_RAND_H
#define OPENVPN_POLARSSL_UTIL_RAND_H

#include <polarssl/entropy_poll.h>
#include <polarssl/ctr_drbg.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>

namespace openvpn {

  class PolarSSLRandom : public RC<thread_unsafe_refcount> {
  public:
    OPENVPN_EXCEPTION(rand_error_polarssl);

    typedef boost::intrusive_ptr<PolarSSLRandom> Ptr;

    PolarSSLRandom()
    {
      if (ctr_drbg_init(&ctx, entropy_poll, NULL, NULL, 0) < 0)
	throw rand_error_polarssl("CTR_DRBG init");
    }

    const char *name() const {
      return "CTR_DRBG";
    }

    void rand_bytes(unsigned char *buf, const size_t size)
    {
      if (ctr_drbg_random(&ctx, buf, size) < 0)
	throw rand_error_polarssl("CTR_DRBG rand_bytes");
    }

  private:
    static int entropy_poll(void *data, unsigned char *output, size_t len)
    {
      size_t olen;
      return platform_entropy_poll(data, output, len, &olen);
    }

    ctr_drbg_context ctx;
  };

}

#endif
