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

// Wrap the OpenSSL cipher API defined in <openssl/evp.h> so
// that it can be used as part of the crypto layer of the OpenVPN core.

#ifndef OPENVPN_OPENSSL_CRYPTO_CIPHER_H
#define OPENVPN_OPENSSL_CRYPTO_CIPHER_H

#include <string>

#include <openssl/objects.h>
#include <openssl/evp.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/static_key.hpp>

namespace openvpn {
  namespace OpenSSLCrypto {

    class CipherContext;

    class Cipher
    {
      friend class CipherContext;

    public:
      OPENVPN_EXCEPTION(openssl_cipher_not_found);
      OPENVPN_SIMPLE_EXCEPTION(openssl_cipher_undefined);

      Cipher() : cipher_(NULL) {}

      Cipher(const std::string& name)
      {
	cipher_ = EVP_get_cipherbyname(name.c_str());
	if (!cipher_)
	  throw openssl_cipher_not_found(name);
      }

      std::string name() const
      {
	check_initialized();
	return EVP_CIPHER_name (cipher_);
      }

      size_t key_length() const
      {
	check_initialized();
	return EVP_CIPHER_key_length (cipher_);
      }

      size_t key_length_in_bits() const
      {
	return key_length() * 8;
      }

      size_t iv_length() const
      {
	check_initialized();
	return EVP_CIPHER_iv_length (cipher_);
      }

      size_t block_size() const
      {
	check_initialized();
	return EVP_CIPHER_block_size (cipher_);
      }

      bool defined() const { return cipher_ != NULL; }

    private:
      const EVP_CIPHER *get() const
      {
	check_initialized();
	return cipher_;
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!cipher_)
	  throw openssl_cipher_undefined();
#endif
      }

      const EVP_CIPHER *cipher_;
    };

    class CipherContext : boost::noncopyable
    {
    public:
      OPENVPN_SIMPLE_EXCEPTION(openssl_cipher_mode_error);
      OPENVPN_SIMPLE_EXCEPTION(openssl_cipher_uninitialized);
      OPENVPN_EXCEPTION(openssl_cipher_error);

      // mode parameter for constructor
      enum {
	MODE_UNDEF = -1,
	ENCRYPT = 1,
	DECRYPT = 0
      };

      // OpenSSL cipher constants
      enum {
	MAX_IV_LENGTH = EVP_MAX_IV_LENGTH,
	CIPH_CBC_MODE = EVP_CIPH_CBC_MODE
      };

      CipherContext()
	: initialized(false)
      {
      }

      ~CipherContext() { erase() ; }

      void init(const Cipher& cipher, const unsigned char *key, const int mode)
      {
	// check that mode is valid
	if (!(mode == ENCRYPT || mode == DECRYPT))
	  throw openssl_cipher_mode_error();
	erase();
	EVP_CIPHER_CTX_init (&ctx);
	if (!EVP_CipherInit_ex (&ctx, cipher.get(), NULL, key, NULL, mode))
	  {
	    openssl_clear_error_stack();
	    throw openssl_cipher_error("EVP_CipherInit_ex (init)");
	  }
	initialized = true;
      }

      void reset(const unsigned char *iv)
      {
	check_initialized();
	if (!EVP_CipherInit_ex (&ctx, NULL, NULL, NULL, iv, -1))
	  {
	    openssl_clear_error_stack();
	    throw openssl_cipher_error("EVP_CipherInit_ex (reset)");
	  }
      }

      bool update(unsigned char *out, const size_t max_out_size,
		  const unsigned char *in, const size_t in_size,
		  size_t& out_acc)
      {
	check_initialized();
	int outlen;
	if (EVP_CipherUpdate (&ctx, out, &outlen, in, int(in_size)))
	  {
	    out_acc += outlen;
	    return true;
	  }
	else
	  {
	    openssl_clear_error_stack();
	    return false;
	  }
      }

      bool final(unsigned char *out, const size_t max_out_size, size_t& out_acc)
      {
	check_initialized();
	int outlen;
	if (EVP_CipherFinal_ex (&ctx, out, &outlen))
	  {
	    out_acc += outlen;
	    return true;
	  }
	else
	  {
	    openssl_clear_error_stack();
	    return false;
	  }
      }

      bool is_initialized() const { return initialized; }

      size_t iv_length() const
      {
	check_initialized();
	return EVP_CIPHER_CTX_iv_length (&ctx);
      }

      size_t block_size() const
      {
	check_initialized();
	return EVP_CIPHER_CTX_block_size (&ctx);
      }

      // return cipher mode (such as CIPH_CBC_MODE, etc.)
      int cipher_mode() const
      {
	check_initialized();
	return EVP_CIPHER_CTX_mode (&ctx);  
      }

    private:
      void erase()
      {
	if (initialized)
	  {
	    EVP_CIPHER_CTX_cleanup(&ctx);
	    initialized = false;
	  }
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!initialized)
	  throw openssl_cipher_uninitialized();
#endif
      }

      EVP_CIPHER_CTX ctx;
      bool initialized;
    };
  }
}

#endif
