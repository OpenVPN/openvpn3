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

// Wrap the PolarSSL HMAC API defined in <polarssl/md.h> so
// that it can be used as part of the crypto layer of the OpenVPN core.

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

      HMACContext(const Digest& digest, const unsigned char *key, const size_t key_size)
	: initialized(false)
      {
	init(digest, key, key_size);
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
