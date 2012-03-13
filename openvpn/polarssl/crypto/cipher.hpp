#ifndef OPENVPN_POLARSSL_CRYPTO_CIPHER_H
#define OPENVPN_POLARSSL_CRYPTO_CIPHER_H

#include <string>

#include <polarssl/cipher.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/static_key.hpp>

namespace openvpn {
  namespace PolarSSLCrypto {
    class Cipher
    {
      friend class CipherContext;

    public:
      OPENVPN_SIMPLE_EXCEPTION(cipher_not_found);
      OPENVPN_SIMPLE_EXCEPTION(cipher_undefined);

      Cipher() : cipher_(NULL) {}

      Cipher(const std::string& name)
      {
	cipher_ = cipher_info_from_string(name.c_str());
	if (!cipher_)
	  throw cipher_not_found();
      }

      const char *name() const
      {
	check_initialized();
	return cipher_->name;
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
	  throw cipher_undefined();
#endif
      }

      const cipher_info_t *cipher_;
    };

    class CipherContext : boost::noncopyable
    {
    public:
      OPENVPN_SIMPLE_EXCEPTION(cipher_mode_error);
      OPENVPN_SIMPLE_EXCEPTION(cipher_uninitialized);
      OPENVPN_EXCEPTION(cipher_polarssl_error);

      // mode parameter for constructor
      enum {
	MODE_UNDEF = POLARSSL_OPERATION_NONE,
	ENCRYPT = POLARSSL_ENCRYPT,
	DECRYPT = POLARSSL_DECRYPT
      };

      // OpenSSL cipher constants
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
	  throw cipher_mode_error();

	// get cipher type
	const cipher_info_t *ci = cipher.get();

	// initialize cipher context with cipher type
	if (cipher_init_ctx(&ctx, ci) < 0)
	  throw cipher_polarssl_error("cipher_init_ctx");

	// set key and encrypt/decrypt mode
	if (cipher_setkey(&ctx, key, ci->key_length, (operation_t)mode) < 0)
	  throw cipher_polarssl_error("cipher_setkey");

	initialized = true;
      }

      void reset(const unsigned char *iv)
      {
	check_initialized();
	if (cipher_reset(&ctx, iv) < 0)
	  throw cipher_polarssl_error("cipher_reset");
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
	  throw cipher_uninitialized();
#endif
      }

      cipher_context_t ctx;
      bool initialized;
    };
  }
}

#endif
