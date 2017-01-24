// Private Gateway
// Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
// All rights reserved

#ifndef OPENVPN_CRYPTO_TOKENENCRYPT_H
#define OPENVPN_CRYPTO_TOKENENCRYPT_H

#include <string>
#include <atomic>
#include <cstdint> // for std::uint8_t

#include <openssl/objects.h>
#include <openssl/evp.h>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/random/randapi.hpp>
#include <openvpn/openssl/util/error.hpp>

namespace openvpn {
  class TokenEncrypt
  {
  public:
    static constexpr size_t TOK_SIZE = 32;

    struct Key
    {
      Key(RandomAPI& rng)
      {
	rng.assert_crypto();
	rng.rand_bytes(data, sizeof(data));
      }

      std::uint8_t data[TOK_SIZE];
    };

    // mode parameter for constructor
    enum {
      ENCRYPT = 1,
      DECRYPT = 0
    };

    TokenEncrypt(const Key& key, const int mode)
    {
      static_assert(TOK_SIZE % 16 == 0, "TOK_SIZE must be multiple of AES block size");
      EVP_CIPHER_CTX_init(&ctx);
      if (!EVP_CipherInit_ex(&ctx, EVP_aes_128_ecb(), nullptr, key.data, nullptr, mode))
	throw OpenSSLException("TokenEncrypt: EVP_CipherInit_ex[1] failed");
      EVP_CIPHER_CTX_set_padding(&ctx, 0);
    }

    ~TokenEncrypt()
    {
      EVP_CIPHER_CTX_cleanup(&ctx);
    }

    std::string crypt(const std::string& tokstr)
    {
      // convert token to binary
      unsigned char src[TOK_SIZE];
      Buffer srcbuf(src, TOK_SIZE, false);
      try {
	base64->decode(srcbuf, tokstr);
      }
      catch (const std::exception& e)
	{
	  OPENVPN_THROW_EXCEPTION("TokenEncrypt: base64 decode: " << e.what());
	}
      if (srcbuf.size() != TOK_SIZE)
	OPENVPN_THROW_EXCEPTION("TokenEncrypt: wrong input size, actual=" << srcbuf.size() << " expected=" << TOK_SIZE);

      // crypt it
      unsigned char dest[TOK_SIZE];
      int outlen=0;
      if (!EVP_CipherInit_ex (&ctx, nullptr, nullptr, nullptr, nullptr, -1))
	throw OpenSSLException("TokenEncrypt: EVP_CipherInit_ex[2] failed");
      if (!EVP_CipherUpdate(&ctx, dest, &outlen, src, TOK_SIZE))
	throw OpenSSLException("TokenEncrypt: EVP_CipherUpdate failed");
      // NOTE: we skip EVP_CipherFinal_ex because we are running in ECB mode without padding
      if (outlen != TOK_SIZE)
	OPENVPN_THROW_EXCEPTION("TokenEncrypt: unexpected output length=" << outlen);

      // convert result to base64
      return base64->encode(dest, TOK_SIZE);
    }

  private:
    TokenEncrypt(const TokenEncrypt&) = delete;
    TokenEncrypt& operator=(const TokenEncrypt&) = delete;

    EVP_CIPHER_CTX ctx;
  };

  struct TokenEncryptDecrypt
  {
    TokenEncryptDecrypt(const TokenEncrypt::Key& key)
      : encrypt(key, TokenEncrypt::ENCRYPT),
	decrypt(key, TokenEncrypt::DECRYPT)
    {
    }

    TokenEncrypt encrypt;
    TokenEncrypt decrypt;
  };
}

#endif
