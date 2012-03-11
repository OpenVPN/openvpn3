#ifndef OPENVPN_APPLECRYPTO_CRYPTO_EVPDIGEST_H
#define OPENVPN_APPLECRYPTO_CRYPTO_EVPDIGEST_H

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>

#include <openvpn/common/string.hpp>
#include <openvpn/applecrypto/crypto/evpcommon.hpp>

#define OPENVPN_DIGEST_CONTEXT(TYPE) CC_##TYPE##_CTX TYPE##_ctx

#define OPENVPN_DIGEST_DECLARE(TYPE) const EVP_MD_##TYPE TYPE

#define OPENVPN_DIGEST_SELECT(TYPE) \
  if (apple_digest::TYPE.name_match(name)) return &apple_digest::TYPE

#define OPENVPN_DIGEST_CLASS(TYPE) \
  class EVP_MD_##TYPE : public EVP_MD \
  { \
  public: \
    EVP_MD_##TYPE() \
      : EVP_MD(#TYPE, CC_##TYPE##_DIGEST_LENGTH, kCCHmacAlg##TYPE) {}	\
    virtual int DigestInit(EVP_MD_CTX *ctx) const \
    { \
      return CC_##TYPE##_Init(&ctx->u.TYPE##_ctx); \
    } \
    virtual int DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) const \
    { \
      return CC_##TYPE##_Update(&ctx->u.TYPE##_ctx, d, cnt); \
    } \
    virtual int DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) const \
    { \
      const int ret = CC_##TYPE##_Final(md, &ctx->u.TYPE##_ctx); \
      if (s) \
	*s = CC_##TYPE##_DIGEST_LENGTH; \
      return ret; \
    } \
  }

namespace openvpn {
  struct EVP_MD_CTX;

  class EVP_MD
  {
  public:
    int MD_size() const
    {
      return md_size_;
    }

    const char *MD_name() const
    {
      return name_;
    }

    bool name_match(const char *name) const
    {
      return string::strcasecmp(name, name_) == 0;
    }

    int MD_CTX_cleanup(EVP_MD_CTX *ctx) const
    {
      return 1;
    }

    CCHmacAlgorithm algorithm() const { return algorithm_; }

    virtual int DigestInit(EVP_MD_CTX *ctx) const = 0;
    virtual int DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) const = 0;
    virtual int DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) const = 0;

  protected:
    EVP_MD(const char *name, const int md_size, const CCHmacAlgorithm algorithm)
      : name_(name), md_size_(md_size), algorithm_(algorithm) {}

  private:
    const char *name_;
    int md_size_;
    CCHmacAlgorithm algorithm_;
  };

  typedef CC_SHA256_CTX CC_SHA224_CTX;
  typedef CC_SHA512_CTX CC_SHA384_CTX;

  enum {
    EVP_MAX_MD_SIZE = CC_SHA512_DIGEST_LENGTH // largest known is SHA512
  };

  struct EVP_MD_CTX
  {
    const EVP_MD *md;
    union {
      OPENVPN_DIGEST_CONTEXT(MD5);
      OPENVPN_DIGEST_CONTEXT(SHA1);
      OPENVPN_DIGEST_CONTEXT(SHA224);
      OPENVPN_DIGEST_CONTEXT(SHA256);
      OPENVPN_DIGEST_CONTEXT(SHA384);
      OPENVPN_DIGEST_CONTEXT(SHA512);
    } u;
  };

  namespace apple_digest {
    OPENVPN_DIGEST_CLASS(MD5);
    OPENVPN_DIGEST_CLASS(SHA1);
    OPENVPN_DIGEST_CLASS(SHA224);
    OPENVPN_DIGEST_CLASS(SHA256);
    OPENVPN_DIGEST_CLASS(SHA384);
    OPENVPN_DIGEST_CLASS(SHA512);

    OPENVPN_DIGEST_DECLARE(MD5);
    OPENVPN_DIGEST_DECLARE(SHA1);
    OPENVPN_DIGEST_DECLARE(SHA224);
    OPENVPN_DIGEST_DECLARE(SHA256);
    OPENVPN_DIGEST_DECLARE(SHA384);
    OPENVPN_DIGEST_DECLARE(SHA512);
  }

  inline const EVP_MD *EVP_md5() { return &apple_digest::MD5; }
  inline const EVP_MD *EVP_sha1() { return &apple_digest::SHA1; }

  inline const EVP_MD *EVP_get_digestbyname(const char *name)
  {
    OPENVPN_DIGEST_SELECT(MD5);
    OPENVPN_DIGEST_SELECT(SHA1);
    OPENVPN_DIGEST_SELECT(SHA224);
    OPENVPN_DIGEST_SELECT(SHA256);
    OPENVPN_DIGEST_SELECT(SHA384);
    OPENVPN_DIGEST_SELECT(SHA512);
    return NULL;
  }

  inline int EVP_MD_size(const EVP_MD *md)
  {
    return md->MD_size();
  }

  inline const char *EVP_MD_name(const EVP_MD *md)
  {
    return md->MD_name();
  }

  inline int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *md)
  {
    ctx->md = md;
    return md->DigestInit(ctx);
  }

  inline int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
  {
    return ctx->md->DigestUpdate(ctx, d, cnt);
  }

  inline int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
  {
    return ctx->md->DigestFinal(ctx, md, s);
  }

  inline int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
  {
    return ctx->md->MD_CTX_cleanup(ctx);
  }

} // namespace openvpn

#undef OPENVPN_DIGEST_CONTEXT
#undef OPENVPN_DIGEST_DECLARE
#undef OPENVPN_DIGEST_SELECT
#undef OPENVPN_DIGEST_CLASS

#endif // OPENVPN_APPLECRYPTO_CRYPTO_EVPDIGEST_H
