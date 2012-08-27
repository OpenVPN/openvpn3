//
//  hmac.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_APPLECRYPTO_CRYPTO_HMAC_H
#define OPENVPN_APPLECRYPTO_CRYPTO_HMAC_H

#include <string>
#include <cstring>

#include <CommonCrypto/CommonHMAC.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/applecrypto/crypto/digest.hpp>

namespace openvpn {
  namespace AppleCrypto {
    class HMACContext : boost::noncopyable
    {
    public:
      OPENVPN_SIMPLE_EXCEPTION(hmac_uninitialized);
      OPENVPN_SIMPLE_EXCEPTION(hmac_keysize_error);

      enum {
	MAX_HMAC_SIZE = DigestContext::MAX_DIGEST_SIZE,
	MAX_HMAC_KEY_SIZE = 128,
      };

      HMACContext()
      {
	clear();
	need_to_dealloc = false;
      }

      ~HMACContext()
      {
	dealloc();
      }

      void init(const Digest& digest, const unsigned char *key, const size_t key_size)
      {
	clear();
	dealloc();
	info = digest.get();
	alg = info->hmac_alg();
	if (key_size > MAX_HMAC_KEY_SIZE)
	  throw hmac_keysize_error();
	std::memcpy(key_, key, key_size_ = key_size);
	CCHmacInit(&ctx, alg, key_, key_size_);
	initialized = need_to_dealloc = true;
      }

      void reset() // Apple HMAC API is missing reset method, so we have to reinit
      {
	check_initialized();
	dealloc();
	CCHmacInit(&ctx, alg, key_, key_size_);
	need_to_dealloc = true;
      }

      void update(const unsigned char *in, const size_t size)
      {
	check_initialized();
	CCHmacUpdate(&ctx, in, size);
      }

      size_t final(unsigned char *out)
      {
	check_initialized();
	CCHmacFinal(&ctx, out);
	need_to_dealloc = false;
	return info->size();
      }

      size_t size() const
      {
	check_initialized();
	return info->size();
      }

      bool is_initialized() const { return initialized; }

    private:
      void clear()
      {
	initialized = false;
      }

      void dealloc()
      {
	if (need_to_dealloc)
	  {
	    CCHmacFinal(&ctx, NULL);
	    need_to_dealloc = false;
	  }
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!initialized)
	  throw hmac_uninitialized();
#endif
      }

      bool initialized;
      bool need_to_dealloc;
      const DigestInfo *info;
      CCHmacAlgorithm alg;
      size_t key_size_;
      unsigned char key_[MAX_HMAC_KEY_SIZE];
      CCHmacContext ctx;
    };
  }
}

#endif
