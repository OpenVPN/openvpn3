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

// Wrap the PolarSSL cipher API defined in <polarssl/cipher.h> so
// that it can be used as part of the crypto layer of the OpenVPN core.

#ifndef OPENVPN_POLARSSL_CRYPTO_CIPHERGCM_H
#define OPENVPN_POLARSSL_CRYPTO_CIPHERGCM_H

#include <string>

#include <polarssl/gcm.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/likely.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>

namespace openvpn {
  namespace PolarSSLCrypto {
    class CipherContextGCM : boost::noncopyable
    {
    public:
      OPENVPN_EXCEPTION(polarssl_gcm_error);

      // PolarSSL cipher constants
      enum {
	IV_LEN = 12,
	AUTH_TAG_LEN = 16,
      };

#if 0
      // PolarSSL encrypt/decrypt return values
      enum {
	GCM_AUTH_FAILED = POLARSSL_ERR_GCM_AUTH_FAILED,
	SUCCESS = 0,
      };
#endif

      CipherContextGCM()
	: initialized(false)
      {
      }

      ~CipherContextGCM() { erase() ; }

      void init(const CryptoAlgs::Type alg, const unsigned char *key, const unsigned int keysize)
      {
	erase();

	// get cipher type
	unsigned int ckeysz = 0;
	const cipher_id_t cid = cipher_type(alg, ckeysz);
	if (ckeysz > keysize)
	  throw polarssl_gcm_error("insufficient key material");

	// initialize cipher context
	if (gcm_init(&ctx, cid, key, ckeysz * 8) < 0)
	  throw polarssl_gcm_error("gcm_init");

	initialized = true;
      }

      // encrypt in-place
      void encrypt(unsigned char *data,
		   size_t length,
		   const unsigned char *iv,
		   unsigned char *tag,
		   const unsigned char *ad,
		   size_t ad_len)
      {
	check_initialized();
	const int status = gcm_crypt_and_tag(&ctx, GCM_ENCRYPT, length, iv, IV_LEN, ad, ad_len,
					     data, data, AUTH_TAG_LEN, tag);
	if (unlikely(status))
	  OPENVPN_THROW(polarssl_gcm_error, "gcm_crypt_and_tag failed with status=" << status);
      }

      // input and output may NOT be equal
      bool decrypt(const unsigned char *input,
		  unsigned char *output,
		  size_t length,
		  const unsigned char *iv,
		  unsigned char *tag,
		  const unsigned char *ad,
		  size_t ad_len)
      {
	check_initialized();
	const int status = gcm_auth_decrypt(&ctx, length, iv, IV_LEN, ad, ad_len, tag,
					    AUTH_TAG_LEN, input, output);
	return status == 0;
      }

      bool is_initialized() const { return initialized; }

    private:
      static cipher_id_t cipher_type(const CryptoAlgs::Type alg, unsigned int& keysize)
      {
	switch (alg)
	  {
	  case CryptoAlgs::AES_128_GCM:
	    keysize = 16;
	    return POLARSSL_CIPHER_ID_AES;
	  case CryptoAlgs::AES_192_GCM:
	    keysize = 24;
	    return POLARSSL_CIPHER_ID_AES;
	  case CryptoAlgs::AES_256_GCM:
	    keysize = 32;
	    return POLARSSL_CIPHER_ID_AES;
	  default:
	    OPENVPN_THROW(polarssl_gcm_error, CryptoAlgs::name(alg) << ": not usable");
	  }
      }

      void erase()
      {
	if (initialized)
	  {
	    gcm_free(&ctx);
	    initialized = false;
	  }
      }

      void check_initialized() const
      {
	if (unlikely(!initialized))
	  throw polarssl_gcm_error("uninitialized");
      }

      bool initialized;
      gcm_context ctx;
    };
  }
}

#endif
