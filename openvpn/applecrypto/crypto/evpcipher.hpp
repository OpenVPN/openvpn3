#ifndef OPENVPN_APPLECRYPTO_CRYPTO_EVPCIPHER_H
#define OPENVPN_APPLECRYPTO_CRYPTO_EVPCIPHER_H

#include <cstring>
#include <CommonCrypto/CommonCryptor.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/applecrypto/crypto/evpcommon.hpp>

#define OPENVPN_CIPHER_SELECT(TYPE) \
  if (apple_cipher::TYPE.name_match(name)) return &apple_cipher::TYPE

namespace openvpn {

  enum {
    EVP_MAX_IV_LENGTH = 16,
    EVP_CIPH_CBC_MODE = 0,
  };

  class EVP_CIPHER
  {
  public:
    EVP_CIPHER(const char *name, const int key_size, const int iv_length, const int block_size, const CCAlgorithm algorithm)
      : name_(name), key_size_(key_size), iv_length_(iv_length), block_size_(block_size), algorithm_(algorithm) {}

    bool name_match(const char *name) const
    {
      return string::strcasecmp(name, name_) == 0;
    }

    const char *CIPHER_name() const { return name_; }
    int CIPHER_key_length() const { return key_size_; }
    int CIPHER_iv_length() const { return iv_length_; }
    int CIPHER_block_size() const { return block_size_; }

    CCAlgorithm algorithm() const { return algorithm_; }

  private:
    const char *name_;
    int key_size_;
    int iv_length_;
    int block_size_;
    CCAlgorithm algorithm_;
  };

  struct EVP_CIPHER_CTX
  {
    const EVP_CIPHER *cipher;
    CCCryptorRef cref;
    CCCryptorStatus error;
  };

  namespace apple_cipher {
    EVP_CIPHER aes128("AES-128-CBC", kCCKeySizeAES128, kCCBlockSizeAES128, kCCBlockSizeAES128, kCCAlgorithmAES128);
    EVP_CIPHER aes192("AES-192-CBC", kCCKeySizeAES192, kCCBlockSizeAES128, kCCBlockSizeAES128, kCCAlgorithmAES128);
    EVP_CIPHER aes256("AES-256-CBC", kCCKeySizeAES256, kCCBlockSizeAES128, kCCBlockSizeAES128, kCCAlgorithmAES128);
    EVP_CIPHER des3("DES-EDE3-CBC", kCCKeySize3DES, kCCBlockSize3DES, kCCBlockSize3DES, kCCAlgorithm3DES);
  }

  const EVP_CIPHER *EVP_get_cipherbyname(const char *name)
  {
    OPENVPN_CIPHER_SELECT(aes128);
    OPENVPN_CIPHER_SELECT(aes192);
    OPENVPN_CIPHER_SELECT(aes256);
    OPENVPN_CIPHER_SELECT(des3);
    return NULL;
  }

  inline const char *EVP_CIPHER_name (const EVP_CIPHER *cipher)
  {
    return cipher->CIPHER_name();
  }

  inline int EVP_CIPHER_key_length(const EVP_CIPHER *cipher)
  {
    return cipher->CIPHER_key_length();
  }

  inline int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher)
  {
    return cipher->CIPHER_iv_length();
  }

  inline int EVP_CIPHER_block_size(const EVP_CIPHER *cipher)
  {
    return cipher->CIPHER_block_size();
  }

  inline int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx)
  {
    return ctx->cipher->CIPHER_key_length();
  }

  inline int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx)
  {
    return ctx->cipher->CIPHER_iv_length();
  }

  inline int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx)
  {
    return ctx->cipher->CIPHER_block_size();
  }

  inline int EVP_CIPHER_CTX_mode(const EVP_CIPHER_CTX *ctx)
  {
    return EVP_CIPH_CBC_MODE;
  }

  inline void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx)
  {
    ctx->cipher = NULL;
    ctx->cref = NULL;
    ctx->error = kCCSuccess;
  }

  inline int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *ctx)
  {
    if (ctx->cref)
      CCCryptorRelease(ctx->cref);
    EVP_CIPHER_CTX_init(ctx);
    return 1;
  }

  inline int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
			       const unsigned char *key, const unsigned char *iv,
			       int enc)
  {
    if (enc == -1)
      {
	const CCCryptorStatus status = CCCryptorReset(ctx->cref, iv);
	if (status != kCCSuccess)
	  {
	    ctx->error = status;
	    return 0;
	  }
	return 1;
      }
    else
      {
	const CCCryptorStatus status = CCCryptorCreate(enc ? kCCEncrypt :  kCCDecrypt,
						       cipher->algorithm(),
						       kCCOptionPKCS7Padding,
						       key,
						       cipher->CIPHER_key_length(),
						       NULL,
						       &ctx->cref);
	if (status != kCCSuccess)
	  {
	    ctx->error = status;
	    return 0;
	  }
	ctx->cipher = cipher;
	return 1;
      }
  }

  inline int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
			      int *outl, const unsigned char *in, int inl)
  {
    size_t dataOutMoved;
    const CCCryptorStatus status = CCCryptorUpdate(ctx->cref, in, inl, out, *outl, &dataOutMoved);
    if (status != kCCSuccess)
      {
	ctx->error = status;
	return 0;
      }
    *outl = dataOutMoved;
    return 1;
  }

  int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
  {
    size_t dataOutMoved;
    const CCCryptorStatus status = CCCryptorFinal(ctx->cref, out, *outl, &dataOutMoved);
    if (status != kCCSuccess)
      {
	ctx->error = status;
	return 0;
      }
    *outl = dataOutMoved;
    return 1;
  }

} // namespace openvpn

#undef OPENVPN_CIPHER_SELECT

#endif // OPENVPN_APPLECRYPTO_CRYPTO_EVPCIPHER_H
