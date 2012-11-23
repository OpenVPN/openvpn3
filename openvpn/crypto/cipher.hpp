//
//  cipher.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// General-purpose cipher classes that are independent of the underlying CRYPTO_API

#ifndef OPENVPN_CRYPTO_CIPHER_H
#define OPENVPN_CRYPTO_CIPHER_H

#include <string>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/static_key.hpp>

namespace openvpn {
  template <typename CRYPTO_API>
  class CipherContext
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(cipher_mode_error);
    OPENVPN_SIMPLE_EXCEPTION(cipher_uninitialized);
    OPENVPN_SIMPLE_EXCEPTION(cipher_init_insufficient_key_material);
    OPENVPN_SIMPLE_EXCEPTION(cipher_internal_error);
    OPENVPN_SIMPLE_EXCEPTION(cipher_output_buffer);

  public:
    CipherContext() : mode_(CRYPTO_API::CipherContext::MODE_UNDEF) {}

    CipherContext(const typename CRYPTO_API::Cipher& cipher, const StaticKey& key, const int mode)
      : mode_(CRYPTO_API::CipherContext::MODE_UNDEF)
    {
      init(cipher, key, mode);
    }

    bool defined() const { return ctx.is_initialized(); }

    // size of iv buffer to pass to encrypt_decrypt
    size_t iv_length() const
    {
      return ctx.iv_length();
    }

    // cipher mode (such as CIPH_CBC_MODE, etc.)
    int cipher_mode() const
    {
      return ctx.cipher_mode();
    }

    // size of out buffer to pass to encrypt_decrypt
    size_t output_size(const size_t in_size) const
    {
      return in_size + ctx.block_size();
    }

    void init(const typename CRYPTO_API::Cipher& cipher, const StaticKey& key, const int mode)
    {
      // check that key is large enough
      if (key.size() < cipher.key_length())
	throw cipher_init_insufficient_key_material();

      // This could occur if we were built with a different version of
      // OpenSSL headers than the underlying library.
      if (cipher.iv_length() > CRYPTO_API::CipherContext::MAX_IV_LENGTH)
	throw cipher_internal_error();

      // initialize cipher context with cipher type, key, and encrypt/decrypt mode
      ctx.init(cipher, key.data(), mode);

      // save mode in object
      mode_ = mode;
    }

    size_t encrypt(const unsigned char *iv,
		   unsigned char *out, const size_t out_size,
		   const unsigned char *in, const size_t in_size)
    {
      if (mode_ != CRYPTO_API::CipherContext::ENCRYPT)
	throw cipher_mode_error();
      return encrypt_decrypt(iv, out, out_size, in, in_size);
    }

    size_t decrypt(const unsigned char *iv,
		   unsigned char *out, const size_t out_size,
		   const unsigned char *in, const size_t in_size)
    {
      if (mode_ != CRYPTO_API::CipherContext::DECRYPT)
	throw cipher_mode_error();
      return encrypt_decrypt(iv, out, out_size, in, in_size);
    }

    size_t encrypt_decrypt(const unsigned char *iv,
			   unsigned char *out, const size_t out_size,
			   const unsigned char *in, const size_t in_size)
    {
      if (out_size < output_size(in_size))
	throw cipher_output_buffer();
      ctx.reset(iv);
      size_t outlen = 0;
      if (!ctx.update(out, out_size, in, in_size, outlen))
	return 0;
      if (!ctx.final(out + outlen, out_size - outlen, outlen))
	return 0;
      return outlen;
    }

  private:
    int mode_;
    typename CRYPTO_API::CipherContext ctx;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_CIPHER_H
