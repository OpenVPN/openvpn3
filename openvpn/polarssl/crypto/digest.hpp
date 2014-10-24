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

// Wrap the PolarSSL digest API defined in <polarssl/md.h>
// so that it can be used as part of the crypto layer of the OpenVPN core.

#ifndef OPENVPN_POLARSSL_CRYPTO_DIGEST_H
#define OPENVPN_POLARSSL_CRYPTO_DIGEST_H

#include <string>

#include <polarssl/md.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>

namespace openvpn {
  namespace PolarSSLCrypto {
    class HMACContext;

    class DigestContext : boost::noncopyable
    {
    public:
      friend class HMACContext;

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

      DigestContext(const CryptoAlgs::Type alg)
	: initialized(false)
      {
	init(alg);
      }

      ~DigestContext() { erase() ; }

      void init(const CryptoAlgs::Type alg)
      {
	erase();
	ctx.md_ctx = NULL;
	if (md_init_ctx(&ctx, digest_type(alg)) < 0)
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
      static const md_info_t *digest_type(const CryptoAlgs::Type alg)
      {
	switch (alg)
	  {
	  case CryptoAlgs::MD4:
	    return md_info_from_type(POLARSSL_MD_MD4);
	  case CryptoAlgs::MD5:
	    return md_info_from_type(POLARSSL_MD_MD5);
	  case CryptoAlgs::SHA1:
	    return md_info_from_type(POLARSSL_MD_SHA1);
	  case CryptoAlgs::SHA224:
	    return md_info_from_type(POLARSSL_MD_SHA224);
	  case CryptoAlgs::SHA256:
	    return md_info_from_type(POLARSSL_MD_SHA256);
	  case CryptoAlgs::SHA384:
	    return md_info_from_type(POLARSSL_MD_SHA384);
	  case CryptoAlgs::SHA512:
	    return md_info_from_type(POLARSSL_MD_SHA512);
	  default:
	    OPENVPN_THROW(polarssl_digest_error, CryptoAlgs::name(alg) << ": not usable");
	  }
      }

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
