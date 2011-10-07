#ifndef OPENVPN_CRYPTO_DIGEST
#define OPENVPN_CRYPTO_DIGEST

#include <boost/noncopyable.hpp>

#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/static_key.hpp>

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

    bool defined() const { return digest_ != NULL; }

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
    OPENVPN_SIMPLE_EXCEPTION(digest_output_buffer);

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

    bool is_initialized() const { return initialized; }

    private:
      HMAC_CTX ctx;
      bool initialized;
    };

  public:
    // OpenSSL constants
    enum {
      MAX_HMAC_SIZE = EVP_MAX_MD_SIZE
    };

    HMACContext() {}

    HMACContext(const Digest& digest, const StaticKey& key)
    {
      init(digest, key);
    }

    HMACContext(const HMACContext& ref)
    {
      init(ref.digest_, ref.key_);
    }

    bool defined() const { return ctx.is_initialized(); }

    void operator=(const HMACContext& ref)
    {
      if (this != &ref)
	init(ref.digest_, ref.key_);
    }

    // size of out buffer to pass to hmac
    size_t output_size() const
    {
      return HMAC_size (ctx());
    }

    void init(const Digest& digest, const StaticKey& key)
    {
      // init members
      digest_ = digest;
      key_ = key;
      ctx.erase();

      if (digest.defined())
	{
	  // check that key is large enough
	  if (key_.size() < digest_.size())
	    throw digest_init_insufficient_key_material();

	  // initialize HMAC context with digest type and key
	  ctx.init();
	  HMAC_Init_ex (ctx(), key_.data(), int(digest_.size()), digest_.get(), NULL);
	}
    }

    size_t hmac(unsigned char *out, const size_t out_size,
		const unsigned char *in, const size_t in_size)
    {
      unsigned int outlen;
      HMAC_CTX *c = ctx();
      const unsigned int hmac_size = HMAC_size(c);
      if (out_size != hmac_size)
	throw digest_output_buffer();
      HMAC_Init_ex (c, NULL, 0, NULL, NULL);
      HMAC_Update (c, in, int(in_size));
      HMAC_Final (c, out, &outlen);
      if (outlen != hmac_size)
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
