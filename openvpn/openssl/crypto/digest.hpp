//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Wrap the OpenSSL digest API defined in <openssl/evp.h>
// so that it can be used as part of the crypto layer of the OpenVPN core.

#ifndef OPENVPN_OPENSSL_CRYPTO_DIGEST_H
#define OPENVPN_OPENSSL_CRYPTO_DIGEST_H

#include <string>

#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/md4.h>
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

      std::string name() const
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
      static Digest md4() { return Digest(EVP_md4()); }
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
