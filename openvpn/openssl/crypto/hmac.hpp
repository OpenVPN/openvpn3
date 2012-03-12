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
      OPENVPN_SIMPLE_EXCEPTION(hmac_final_overflow);
      OPENVPN_SIMPLE_EXCEPTION(hmac_openssl_error);

      enum {
	MAX_HMAC_SIZE = EVP_MAX_MD_SIZE
      };

      HMACContext()
	: initialized(false)
      {
      }

      ~HMACContext() { erase() ; }

      void init()
      {
	erase();
	HMAC_CTX_init (&ctx);
	initialized = true;
      }

      void reset(const Digest& digest, const unsigned char *key, const size_t key_size)
      {
	check_initialized();
	if (!HMAC_Init_ex (&ctx, key, int(key_size), digest.get(), NULL))
	  throw hmac_openssl_error();
      }

      void reset()
      {
	check_initialized();
	if (!HMAC_Init_ex (&ctx, NULL, 0, NULL, NULL))
	  throw hmac_openssl_error();
      }

      void erase()
      {
	if (initialized)
	  {
	    HMAC_CTX_cleanup(&ctx);
	    initialized = false;
	  }
      }

      void update(const unsigned char *in, const size_t size)
      {
	check_initialized();
	if (!HMAC_Update(&ctx, in, int(size)))
	  throw hmac_openssl_error();
      }

      size_t final(unsigned char *out, const size_t size)
      {
	check_initialized();
	if (size < size_())
	  throw hmac_final_overflow();
	return final_(out);
      }

      size_t final(unsigned char *out)
      {
	check_initialized();
	return final_(out);
      }

      size_t size() const
      {
	check_initialized();
	return size_();
      }

      bool is_initialized() const { return initialized; }

    private:
      size_t size_() const
      {
	return HMAC_size(&ctx);
      }

      size_t final_(unsigned char *out)
      {
	unsigned int outlen;
	if (!HMAC_Final(&ctx, out, &outlen))
	  throw hmac_openssl_error();
	return outlen;
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
