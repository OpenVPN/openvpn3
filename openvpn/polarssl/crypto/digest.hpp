//
//  digest.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_POLARSSL_CRYPTO_DIGEST_H
#define OPENVPN_POLARSSL_CRYPTO_DIGEST_H

#include <string>

#include <polarssl/md.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {
  namespace PolarSSLCrypto {
    class DigestContext;
    class HMACContext;

    class Digest
    {
      friend class DigestContext;
      friend class HMACContext;

    public:
      OPENVPN_EXCEPTION(polarssl_digest_not_found);
      OPENVPN_SIMPLE_EXCEPTION(polarssl_digest_undefined);

      Digest() : digest_(NULL) {}

      Digest(const std::string& name)
      {
	digest_ = md_info_from_string(name.c_str());
	if (!digest_)
	  throw polarssl_digest_not_found(name);
      }

      const char *name() const
      {
	check_initialized();
	return md_get_name(digest_);
      }

      size_t size() const
      {
	check_initialized();
	return md_get_size(digest_);
      }

      bool defined() const { return digest_ != NULL; }

      // convenience methods for common digests
      static Digest md4() { return Digest(md_info_from_type(POLARSSL_MD_MD4)); }
      static Digest md5() { return Digest(md_info_from_type(POLARSSL_MD_MD5)); }
      static Digest sha1() { return Digest(md_info_from_type(POLARSSL_MD_SHA1)); }

    private:
      Digest(const md_info_t *digest) : digest_(digest) {}

      const md_info_t *get() const
      {
	check_initialized();
	return digest_;
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!digest_)
	  throw polarssl_digest_undefined();
#endif
      }

      const md_info_t *digest_;
    };

    class DigestContext : boost::noncopyable
    {
    public:
      OPENVPN_SIMPLE_EXCEPTION(polarssl_digest_uninitialized);
      OPENVPN_SIMPLE_EXCEPTION(polarssl_digest_final_overflow);
      OPENVPN_EXCEPTION(polarssl_digest_error);

      enum {
	MAX_DIGEST_SIZE = POLARSSL_MD_MAX_SIZE
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
	ctx.md_ctx = NULL;
	if (md_init_ctx(&ctx, digest.get()) < 0)
	  throw polarssl_digest_error("md_init_ctx");
	if (md_starts(&ctx) < 0)
	  throw polarssl_digest_error("md_starts");
	initialized = true;
      }

      void update(const unsigned char *in, const size_t size)
      {
	check_initialized();
	if (md_update(&ctx, in, size) < 0)
	  throw polarssl_digest_error("md_update");
      }

      size_t final(unsigned char *out)
      {
	check_initialized();
	if (md_finish(&ctx, out) < 0)
	  throw polarssl_digest_error("md_finish");
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
	  throw polarssl_digest_uninitialized();
#endif
      }

      bool initialized;
      md_context_t ctx;
    };
  }
}

#endif
