#ifndef OPENVPN_OPENSSL_CRYPTO_HMAC_H
#define OPENVPN_OPENSSL_CRYPTO_HMAC_H

#include <string>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/openssl/crypto/digest.hpp>

namespace openvpn {
  namespace OpenSSLCrypto {
    class HMACContext : boost::noncopyable
    {
    public:
      OPENVPN_SIMPLE_EXCEPTION(hmac_uninitialized);
      OPENVPN_EXCEPTION(hmac_openssl_error);

      enum {
	MAX_HMAC_SIZE = EVP_MAX_MD_SIZE
      };

      HMACContext()
	: initialized(false)
      {
      }

      ~HMACContext() { erase() ; }

      void init(const Digest& digest, const unsigned char *key, const size_t key_size)
      {
	erase();
	HMAC_CTX_init (&ctx);
#if SSLEAY_VERSION_NUMBER >= 0x10000000L
	if (!HMAC_Init_ex (&ctx, key, int(key_size), digest.get(), NULL))
	  throw hmac_openssl_error("HMAC_Init_ex (init)");
#else
	HMAC_Init_ex (&ctx, key, int(key_size), digest.get(), NULL);
#endif
	initialized = true;
      }

      void reset()
      {
	check_initialized();
#if SSLEAY_VERSION_NUMBER >= 0x10000000L
	if (!HMAC_Init_ex (&ctx, NULL, 0, NULL, NULL))
	  throw hmac_openssl_error("HMAC_Init_ex (reset)");
#else
	HMAC_Init_ex (&ctx, NULL, 0, NULL, NULL);
#endif
      }

      void update(const unsigned char *in, const size_t size)
      {
	check_initialized();
#if SSLEAY_VERSION_NUMBER >= 0x10000000L
	if (!HMAC_Update(&ctx, in, int(size)))
	  throw hmac_openssl_error("HMAC_Update");
#else
	HMAC_Update(&ctx, in, int(size));
#endif
      }

      size_t final(unsigned char *out)
      {
	check_initialized();
	unsigned int outlen;
#if SSLEAY_VERSION_NUMBER >= 0x10000000L
	if (!HMAC_Final(&ctx, out, &outlen))
	  throw hmac_openssl_error("HMAC_Final");
#else
	HMAC_Final(&ctx, out, &outlen);
#endif
	return outlen;
      }

      size_t size() const
      {
	check_initialized();
	return size_();
      }

      bool is_initialized() const { return initialized; }

    private:
      void erase()
      {
	if (initialized)
	  {
	    HMAC_CTX_cleanup(&ctx);
	    initialized = false;
	  }
      }

      size_t size_() const
      {
	return HMAC_size(&ctx);
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!initialized)
	  throw hmac_uninitialized();
#endif
      }

      bool initialized;
      HMAC_CTX ctx;
    };
  }
}

#endif
