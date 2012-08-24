//
//  hmac.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_POLARSSL_CRYPTO_HMAC_H
#define OPENVPN_POLARSSL_CRYPTO_HMAC_H

#include <string>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/polarssl/crypto/digest.hpp>

namespace openvpn {
  namespace PolarSSLCrypto {
    class HMACContext : boost::noncopyable
    {
    public:
      OPENVPN_SIMPLE_EXCEPTION(polarssl_hmac_uninitialized);
      OPENVPN_EXCEPTION(polarssl_hmac_error);

      enum {
	MAX_HMAC_SIZE = POLARSSL_MD_MAX_SIZE
      };

      HMACContext()
	: initialized(false)
      {
      }

      ~HMACContext() { erase() ; }

      void init(const Digest& digest, const unsigned char *key, const size_t key_size)
      {
	erase();
	ctx.md_ctx = NULL;
	if (md_init_ctx(&ctx, digest.get()) < 0)
	  throw polarssl_hmac_error("md_init_ctx");
	if (md_hmac_starts(&ctx, key, key_size) < 0)
	  throw polarssl_hmac_error("md_hmac_starts");
	initialized = true;
      }

      void reset()
      {
	check_initialized();
	if (md_hmac_reset(&ctx) < 0)
	  throw polarssl_hmac_error("md_hmac_reset");
      }

      void update(const unsigned char *in, const size_t size)
      {
	check_initialized();
	if (md_hmac_update(&ctx, in, size) < 0)
	  throw polarssl_hmac_error("md_hmac_update");
      }

      size_t final(unsigned char *out)
      {
	check_initialized();
	if (md_hmac_finish(&ctx, out) < 0)
	  throw polarssl_hmac_error("md_hmac_finish");
	return size_();
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
	    md_free_ctx(&ctx);
	    initialized = false;
	  }
      }

      size_t size_() const
      {
	return ctx.md_info->size;
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!initialized)
	  throw polarssl_hmac_uninitialized();
#endif
      }

      bool initialized;
      md_context_t ctx;
    };
  }
}

#endif
