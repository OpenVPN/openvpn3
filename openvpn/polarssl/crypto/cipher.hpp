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

#ifndef OPENVPN_POLARSSL_CRYPTO_CIPHER_H
#define OPENVPN_POLARSSL_CRYPTO_CIPHER_H

#include <string>

#include <polarssl/cipher.h>

#include <boost/noncopyable.hpp>
#include <boost/algorithm/string.hpp> // for boost::algorithm::starts_with, to_upper_copy

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/static_key.hpp>

namespace openvpn {
  namespace PolarSSLCrypto {
    class CipherContext;

    class Cipher
    {
      friend class CipherContext;

    public:
      OPENVPN_EXCEPTION(polarssl_cipher_not_found);
      OPENVPN_SIMPLE_EXCEPTION(polarssl_cipher_undefined);

      Cipher() : cipher_(NULL) {}

      Cipher(const std::string& name)
      {
	const std::string translated_name = openvpn_to_cipher_name(name.c_str());
	cipher_ = cipher_info_from_string(translated_name.c_str());
	if (!cipher_)
	  throw polarssl_cipher_not_found(translated_name);
      }

      std::string name() const
      {
	check_initialized();
	return cipher_name_to_openvpn(cipher_->name);
      }

      size_t key_length() const
      {
	check_initialized();
	return cipher_->key_length / 8;
      }

      size_t key_length_in_bits() const
      {
	check_initialized();
	return cipher_->key_length;
      }

      size_t iv_length() const
      {
	check_initialized();
	return cipher_->iv_size;
      }

      size_t block_size() const
      {
	check_initialized();
	return cipher_->block_size;
      }

      bool defined() const { return cipher_ != NULL; }

    private:
      const cipher_info_t *get() const
      {
	check_initialized();
	return cipher_;
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!cipher_)
	  throw polarssl_cipher_undefined();
#endif
      }

      static std::string openvpn_to_cipher_name(const std::string& name)
      {
	const std::string n = boost::algorithm::to_upper_copy(name);
	if (boost::algorithm::starts_with(n, "BF-"))
	  return "BLOWFISH-" + n.substr(3);
	else
	  return n;
      }

      static std::string cipher_name_to_openvpn(const std::string& name)
      {
	if (boost::algorithm::starts_with(name, "BLOWFISH-"))
	  return "BF-" + name.substr(9);
	else
	  return name;
      }

      const cipher_info_t *cipher_;
    };

    class CipherContext : boost::noncopyable
    {
    public:
      OPENVPN_SIMPLE_EXCEPTION(polarssl_cipher_mode_error);
      OPENVPN_SIMPLE_EXCEPTION(polarssl_cipher_uninitialized);
      OPENVPN_EXCEPTION(polarssl_cipher_error);

      // mode parameter for constructor
      enum {
	MODE_UNDEF = POLARSSL_OPERATION_NONE,
	ENCRYPT = POLARSSL_ENCRYPT,
	DECRYPT = POLARSSL_DECRYPT
      };

      // PolarSSL cipher constants
      enum {
	MAX_IV_LENGTH = POLARSSL_MAX_IV_LENGTH,
	CIPH_CBC_MODE = POLARSSL_MODE_CBC
      };

      CipherContext()
	: initialized(false)
      {
      }

      ~CipherContext() { erase() ; }

      void init()
      {
      }

      void init(const Cipher& cipher, const unsigned char *key, const int mode)
      {
	erase();

	// check that mode is valid
	if (!(mode == ENCRYPT || mode == DECRYPT))
	  throw polarssl_cipher_mode_error();

	// get cipher type
	const cipher_info_t *ci = cipher.get();

	// initialize cipher context with cipher type
	if (cipher_init_ctx(&ctx, ci) < 0)
	  throw polarssl_cipher_error("cipher_init_ctx");

	// set key and encrypt/decrypt mode
	if (cipher_setkey(&ctx, key, ci->key_length, (operation_t)mode) < 0)
	  throw polarssl_cipher_error("cipher_setkey");

	initialized = true;
      }

      void reset(const unsigned char *iv)
      {
	check_initialized();
	if (cipher_reset(&ctx) < 0)
	  throw polarssl_cipher_error("cipher_reset");
	if (cipher_set_iv(&ctx, iv, iv_length()))
	  throw polarssl_cipher_error("cipher_set_iv");
      }

      bool update(unsigned char *out, const size_t max_out_size,
		  const unsigned char *in, const size_t in_size,
		  size_t& out_acc)
      {
	check_initialized();
	size_t outlen;
	if (cipher_update(&ctx, in, in_size, out, &outlen) >= 0)
	  {
	    out_acc += outlen;
	    return true;
	  }
	else
	  return false;
      }

      bool final(unsigned char *out, const size_t max_out_size, size_t& out_acc)
      {
	check_initialized();
	size_t outlen;
	if (cipher_finish (&ctx, out, &outlen) >= 0)
	  {
	    out_acc += outlen;
	    return true;
	  }
	else
	  return false;
      }

      bool is_initialized() const { return initialized; }

      size_t iv_length() const
      {
	check_initialized();
	return cipher_get_iv_size(&ctx);
      }

      size_t block_size() const
      {
	check_initialized();
	return cipher_get_block_size(&ctx);
      }

      // return cipher mode (such as CIPH_CBC_MODE, etc.)
      int cipher_mode() const
      {
	check_initialized();
	return cipher_get_cipher_mode(&ctx);
      }

    private:
      void erase()
      {
	if (initialized)
	  {
	    cipher_free_ctx(&ctx);
	    initialized = false;
	  }
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!initialized)
	  throw polarssl_cipher_uninitialized();
#endif
      }

      cipher_context_t ctx;
      bool initialized;
    };
  }
}

#endif
