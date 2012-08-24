//
//  digest.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_OPENSSL_CRYPTO_DIGEST_H
#define OPENVPN_OPENSSL_CRYPTO_DIGEST_H

#include <string>

#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {
  namespace OpenSSLCrypto {

    class HMACContext;

    class Digest
    {
      friend class DigestContext;
      friend class HMACContext;

    public:
      OPENVPN_EXCEPTION(openssl_digest_not_found);
      OPENVPN_SIMPLE_EXCEPTION(openssl_digest_undefined);

      Digest() : digest_(NULL) {}

      Digest(const std::string& name)
      {
	digest_ = EVP_get_digestbyname(name.c_str());
	if (!digest_)
	  throw openssl_digest_not_found(name);
      }

      const char *name() const
      {
	check_initialized();
	return EVP_MD_name(digest_);
      }

      size_t size() const
      {
	check_initialized();
	return EVP_MD_size(digest_);
      }

      bool defined() const { return digest_ != NULL; }

      // convenience methods for common digests
      static Digest md5() { return Digest(EVP_md5()); }
      static Digest sha1() { return Digest(EVP_sha1()); }

    private:
      Digest(const EVP_MD *digest) : digest_(digest) {}
      const EVP_MD *get() const
      {
	check_initialized();
	return digest_;
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!digest_)
	  throw openssl_digest_undefined();
#endif
      }

      const EVP_MD *digest_;
    };

    class DigestContext : boost::noncopyable
    {
    public:
      OPENVPN_SIMPLE_EXCEPTION(openssl_digest_uninitialized);
      OPENVPN_EXCEPTION(openssl_digest_error);

      enum {
	MAX_DIGEST_SIZE = EVP_MAX_MD_SIZE
      };

      DigestContext()
	: initialized(false)
      {
      }

      DigestContext(const Digest& digest)
	: initialized(false)
      {
	init(digest);
      }

      ~DigestContext() { erase() ; }

      void init(const Digest& digest)
      {
	erase();
	if (!EVP_DigestInit(&ctx, digest.get()))
	  {
	    openssl_clear_error_stack();
	    throw openssl_digest_error("EVP_DigestInit");
	  }
	initialized = true;
      }

      void update(const unsigned char *in, const size_t size)
      {
	check_initialized();
	if (!EVP_DigestUpdate(&ctx, in, int(size)))
	  {
	    openssl_clear_error_stack();
	    throw openssl_digest_error("EVP_DigestUpdate");
	  }
      }

      size_t final(unsigned char *out)
      {
	check_initialized();
	unsigned int outlen;
	if (!EVP_DigestFinal(&ctx, out, &outlen))
	  {
	    openssl_clear_error_stack();
	    throw openssl_digest_error("EVP_DigestFinal");
	  }
	return outlen;
      }

      size_t size() const
      {
	check_initialized();
	return EVP_MD_CTX_size(&ctx);
      }

      bool is_initialized() const { return initialized; }

    private:
      void erase()
      {
	if (initialized)
	  {
	    EVP_MD_CTX_cleanup(&ctx);
	    initialized = false;
	  }
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!initialized)
	  throw openssl_digest_uninitialized();
#endif
      }

      bool initialized;
      EVP_MD_CTX ctx;
    };
  }
}

#endif
