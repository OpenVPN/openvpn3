#ifndef OPENVPN_CRYPTO_CIPHER
#define OPENVPN_CRYPTO_CIPHER

#include <boost/noncopyable.hpp>

#include <openssl/objects.h>
#include <openssl/evp.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/static_key.hpp>

namespace openvpn {
  class Cipher
  {
    friend class CipherContext;

  public:
    OPENVPN_SIMPLE_EXCEPTION(cipher_not_found);
    OPENVPN_SIMPLE_EXCEPTION(cipher_undefined);

    Cipher() : cipher_(NULL) {}

    Cipher(const char *name)
    {
      cipher_ = EVP_get_cipherbyname(name);
      if (!cipher_)
	throw cipher_not_found();
    }

    const char *name() const
    {
      if (!cipher_)
	throw cipher_undefined();
      return OBJ_nid2sn (EVP_CIPHER_nid (cipher_));
    }

    size_t key_length() const
    {
      if (!cipher_)
	throw cipher_undefined();
      return EVP_CIPHER_key_length (cipher_);
    }

  private:
    const EVP_CIPHER *get() const { return cipher_; }

    const EVP_CIPHER *cipher_;
  };

  class CipherContext
  {
  public:
    // mode parameter for constructor
    enum {
      ENCRYPT = 1,
      DECRYPT = 0
    };

    OPENVPN_SIMPLE_EXCEPTION(cipher_init);
    OPENVPN_SIMPLE_EXCEPTION(cipher_update);
    OPENVPN_SIMPLE_EXCEPTION(cipher_final);
    OPENVPN_SIMPLE_EXCEPTION(cipher_mode);
    OPENVPN_SIMPLE_EXCEPTION(cipher_uninitialized);
    OPENVPN_SIMPLE_EXCEPTION(cipher_init_insufficient_key_material);

    class EVP_CIPHER_CTX_wrapper : boost::noncopyable
    {
    public:
      EVP_CIPHER_CTX_wrapper()
	: initialized(false)
      {
      }

      ~EVP_CIPHER_CTX_wrapper() { erase() ; }

      void init()
      {
	erase();
	EVP_CIPHER_CTX_init (&ctx);
	initialized = true;
      }

      void erase()
      {
	if (initialized)
	  {
	    EVP_CIPHER_CTX_cleanup(&ctx);
	    initialized = false;
	  }
      }

      EVP_CIPHER_CTX* operator()() {
	if (!initialized)
	  throw cipher_uninitialized();
	return &ctx;
      }

      const EVP_CIPHER_CTX* operator()() const {
	if (!initialized)
	  throw cipher_uninitialized();
	return &ctx;
      }

    private:
      EVP_CIPHER_CTX ctx;
      bool initialized;
    };

  public:
    CipherContext() {}

    CipherContext(const Cipher& cipher, const StaticKey& key, const int mode)
    {
      init(cipher, key, mode);
    }

    CipherContext(const CipherContext& ref)
    {
      init(ref.cipher_, ref.key_, ref.mode_);
    }

    void operator=(const CipherContext& ref)
    {
      if (this != &ref)
	init(ref.cipher_, ref.key_, ref.mode_);
    }

    void init(const Cipher& cipher, const StaticKey& key, const int mode)
    {
      cipher_ = cipher;
      key_ = key;
      mode_ = mode;
      ctx.erase();

      // check that key is large enough
      if (key_.size() < cipher_.key_length())
	throw cipher_init_insufficient_key_material();

      // check that mode is valid
      if (!(mode_ == ENCRYPT || mode_ == DECRYPT))
	throw cipher_mode();

      // initialize cipher context with cipher type, key, and encrypt/decrypt mode
      ctx.init();
      if (!EVP_CipherInit_ex (ctx(), cipher_.get(), NULL, key_.data(), NULL, mode_))
	throw cipher_init();
    }

    // size of iv buffer to pass to encrypt_decrypt
    size_t iv_size() const
    {
      return EVP_CIPHER_CTX_iv_length (ctx());
    }

    // size of out buffer to pass to encrypt_decrypt
    size_t out_max_size(const size_t inlen) const
    {
      return inlen + EVP_CIPHER_CTX_block_size(ctx());
    }

    size_t encrypt_decrypt(unsigned char *out, const unsigned char *iv, const unsigned char *in, const size_t inlen)
    {
      int outlen, tmplen;

      if (!EVP_CipherInit_ex (ctx(), NULL, NULL, NULL, iv, -1))
	throw cipher_init();
      if (!EVP_CipherUpdate (ctx(), out, &outlen, in, int(inlen)))
	throw cipher_update();
      if (!EVP_CipherFinal_ex (ctx(), out + outlen, &tmplen))
	throw cipher_final();
      return outlen + tmplen;
    }

  private:
    Cipher cipher_;
    StaticKey key_;
    int mode_;
    EVP_CIPHER_CTX_wrapper ctx;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_CIPHER
