#ifndef OPENVPN_APPLECRYPTO_EVPHMAC_H
#define OPENVPN_APPLECRYPTO_EVPHMAC_H

#include <cstring>
#include <CommonCrypto/CommonHMAC.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/applecrypto/evpcommon.hpp>
#include <openvpn/applecrypto/evpdigest.hpp>

namespace openvpn {

  OPENVPN_SIMPLE_EXCEPTION(hmac_init_error);

  enum {
    HMAC_MAX_MD_CBLOCK = 128  // largest known is SHA512
  };

  struct HMAC_CTX
  {
    const EVP_MD *md;
    size_t key_length;
    unsigned char key[HMAC_MAX_MD_CBLOCK];
    CCHmacContext ctx;
  };

  inline int HMAC_size(const HMAC_CTX *ctx)
  {
    return ctx->md->MD_size();
  }

  inline void HMAC_CTX_init(HMAC_CTX *ctx)
  {
    ctx->md = NULL;
  }

  inline void HMAC_CTX_cleanup(HMAC_CTX *ctx)
  {
    std::memset(ctx, 0, sizeof(HMAC_CTX));
  }

  inline void HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl)
  {
    if (key)
      {
	if (len > HMAC_MAX_MD_CBLOCK)
	  throw hmac_init_error();
	ctx->md = md;
	std::memcpy(ctx->key, key, len);
	ctx->key_length = len;
      }
    if (!ctx->md)
      throw hmac_init_error();

    CCHmacInit(&ctx->ctx, ctx->md->algorithm(), ctx->key, ctx->key_length);
  }

  inline void HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len)
  {
    CCHmacUpdate(&ctx->ctx, data, len);
  }

  inline void HMAC_Final(HMAC_CTX *ctx, unsigned char *out, unsigned int *len)
  {
    CCHmacFinal(&ctx->ctx, out);
    if (len)
      *len = HMAC_size(ctx);
  }

} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_EVPHMAC_H
