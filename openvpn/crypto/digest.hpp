#ifndef OPENVPN_CRYPTO_DIGEST
#define OPENVPN_CRYPTO_DIGEST

#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {
  class Digest
  {
    friend class HMACContext;

  public:
    OPENVPN_SIMPLE_EXCEPTION(digest_not_found);
    OPENVPN_SIMPLE_EXCEPTION(digest_undefined);

    Digest() : digest_(NULL) {}

    Digest(const char *name)
    {
      digest_ = EVP_get_digestbyname(name);
      if (!digest_)
	throw digest_not_found();
    }

    const char *name() const
    {
      if (!digest_)
	throw digest_undefined();
      return OBJ_nid2sn (EVP_MD_nid (digest_));
    }

    size_t size() const
    {
      if (!digest_)
	throw digest_undefined();
      return EVP_MD_size (digest_);
    }

  private:
    const EVP_MD *get() const { return digest_; }

    const EVP_MD *digest_;
  };

  class HMACContext
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(digest_init_insufficient_key_material);
    OPENVPN_SIMPLE_EXCEPTION(hmac_size_inconsistency);
    OPENVPN_SIMPLE_EXCEPTION(hmac_uninitialized);

  private:
    class HMAC_CTX_wrapper : boost::noncopyable
    {
    public:
      HMAC_CTX_wrapper()
	: initialized(false)
      {
      }

      ~HMAC_CTX_wrapper() { erase() ; }

      void init()
      {
	erase();
	HMAC_CTX_init (&ctx);
	initialized = true;
      }

      void erase()
      {
	if (initialized)
	  {
	    HMAC_CTX_cleanup(&ctx);
	    initialized = false;
	  }
      }

      HMAC_CTX* operator()() {
	if (!initialized)
	  throw hmac_uninitialized();
	return &ctx;
      }

      const HMAC_CTX* operator()() const {
	if (!initialized)
	  throw hmac_uninitialized();
	return &ctx;
      }

    private:
      HMAC_CTX ctx;
      bool initialized;
    };

  public:
    HMACContext() {}

    HMACContext(const Digest& digest, const StaticKey& key)
    {
      init(digest, key);
    }

    HMACContext(const HMACContext& ref)
    {
      init(ref.digest_, ref.key_);
    }

    void operator=(const HMACContext& ref)
    {
      if (this != &ref)
	init(ref.digest_, ref.key_);
    }

    void init(const Digest& digest, const StaticKey& key)
    {
      // init members
      digest_ = digest;
      key_ = key;
      ctx.erase();

      // check that key is large enough
      if (key_.size() < digest_.size())
	throw digest_init_insufficient_key_material();

      // initialize HMAC context with digest type and key
      ctx.init();
      HMAC_Init_ex (ctx(), key_.data(), int(key_.size()), digest_.get(), NULL);
    }

    // size of out buffer to pass to hmac
    size_t out_size() const
    {
      return HMAC_size (ctx());
    }

    size_t hmac(unsigned char *out, const unsigned char *in, const size_t inlen)
    {
      unsigned int outlen;

      HMAC_Init_ex (ctx(), NULL, 0, NULL, NULL);
      HMAC_Update (ctx(), in, int(inlen));
      HMAC_Final (ctx(), out, &outlen);
      if (outlen != static_cast<unsigned int>(HMAC_size(ctx())))
	throw hmac_size_inconsistency();
      return outlen;
    }

  private:
    Digest digest_;
    StaticKey key_;
    HMAC_CTX_wrapper ctx;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_DIGEST
