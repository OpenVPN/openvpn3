#ifndef OPENVPN_CRYPTO_CIPHER
#define OPENVPN_CRYPTO_CIPHER

#include <boost/noncopyable.hpp>

#include <openvpn/gencrypto/evpcipher.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/protostats.hpp>

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
      return EVP_CIPHER_name (cipher_);
    }

    size_t key_length() const
    {
      if (!cipher_)
	throw cipher_undefined();
      return EVP_CIPHER_key_length (cipher_);
    }

    bool defined() const { return cipher_ != NULL; }

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

    // OpenSSL cipher constants
    enum {
      MAX_IV_SIZE = EVP_MAX_IV_LENGTH,
      CIPH_CBC_MODE = EVP_CIPH_CBC_MODE
    };

    OPENVPN_SIMPLE_EXCEPTION(cipher_init);
    OPENVPN_SIMPLE_EXCEPTION(cipher_update);
    OPENVPN_SIMPLE_EXCEPTION(cipher_final);
    OPENVPN_SIMPLE_EXCEPTION(cipher_mode_error);
    OPENVPN_SIMPLE_EXCEPTION(cipher_uninitialized);
    OPENVPN_SIMPLE_EXCEPTION(cipher_init_insufficient_key_material);
    OPENVPN_SIMPLE_EXCEPTION(cipher_internal_error);
    OPENVPN_SIMPLE_EXCEPTION(cipher_output_buffer);

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

      bool is_initialized() const { return initialized; }

    private:
      EVP_CIPHER_CTX ctx;
      bool initialized;
    };

  public:
    CipherContext() : mode_(-1) {}

    CipherContext(const Cipher& cipher, const StaticKey& key, const int mode, const ProtoStats::Ptr& stats)
    {
      init(cipher, key, mode, stats);
    }

    CipherContext(const CipherContext& ref)
    {
      init(ref.cipher_, ref.key_, ref.mode_, ref.stats_);
    }

    bool defined() const { return ctx.is_initialized(); }

    void operator=(const CipherContext& ref)
    {
      if (this != &ref)
	init(ref.cipher_, ref.key_, ref.mode_, ref.stats_);
    }

    // size of iv buffer to pass to encrypt_decrypt
    size_t iv_size() const
    {
      return EVP_CIPHER_CTX_iv_length (ctx());
    }

    // cipher mode (such as CBC, etc.)
    int cipher_mode() const
    {
      return EVP_CIPHER_CTX_mode (ctx());  
    }

    // size of out buffer to pass to encrypt_decrypt
    size_t output_size(const size_t in_size) const
    {
      return in_size + EVP_CIPHER_CTX_block_size(ctx());
    }

    void init(const Cipher& cipher, const StaticKey& key, const int mode, const ProtoStats::Ptr& stats)
    {
      cipher_ = cipher;
      key_ = key;
      mode_ = mode;
      stats_ = stats;
      ctx.erase();

      if (cipher.defined())
	{
	  // check that key is large enough
	  if (key_.size() < cipher_.key_length())
	    throw cipher_init_insufficient_key_material();

	  // check that mode is valid
	  if (!(mode_ == ENCRYPT || mode_ == DECRYPT))
	    throw cipher_mode_error();

	  // initialize cipher context with cipher type, key, and encrypt/decrypt mode
	  ctx.init();
	  try
	    {
	      if (!EVP_CipherInit_ex (ctx(), cipher_.get(), NULL, key_.data(), NULL, mode_))
		throw cipher_init();

	      // This could occur if we were built with a different version of
	      // OpenSSL headers than the underlying library.
	      if (iv_size() > MAX_IV_SIZE)
		throw cipher_internal_error();
	    }
	  catch (...)
	    {
	      ctx.erase();
	      throw;
	    }
	}
    }

    size_t encrypt(const unsigned char *iv,
		   unsigned char *out, const size_t out_size,
		   const unsigned char *in, const size_t in_size)
    {
      if (mode_ != ENCRYPT)
	throw cipher_mode_error();
      return encrypt_decrypt(iv, out, out_size, in, in_size);
    }

    size_t decrypt(const unsigned char *iv,
		   unsigned char *out, const size_t out_size,
		   const unsigned char *in, const size_t in_size)
    {
      if (mode_ != DECRYPT)
	throw cipher_mode_error();
      return encrypt_decrypt(iv, out, out_size, in, in_size);
    }

    size_t encrypt_decrypt(const unsigned char *iv,
			   unsigned char *out, const size_t out_size,
			   const unsigned char *in, const size_t in_size)
    {
      EVP_CIPHER_CTX *c = ctx();
      if (out_size < output_size(in_size))
	throw cipher_output_buffer();
      if (!EVP_CipherInit_ex (c, NULL, NULL, NULL, iv, -1))
	{
	  error();
	  throw cipher_init();
	}
      int outlen = out_size; // NOTE: minor change to OpenSSL semantics, pass size of output buffer
      if (!EVP_CipherUpdate (c, out, &outlen, in, int(in_size)))
	{
	  error();
	  throw cipher_update();
	}
      int tmplen = out_size - outlen; // NOTE: minor change to OpenSSL semantics, pass size of output buffer
      if (!EVP_CipherFinal_ex (c, out + outlen, &tmplen))
	{
	  error();
	  throw cipher_final();
	}
      return outlen + tmplen;
    }

  private:
    void error()
    {
      if (stats_)
	stats_->error(ProtoStats::CRYPTO_ERRORS);
    }

    Cipher cipher_;
    StaticKey key_;
    int mode_;
    EVP_CIPHER_CTX_wrapper ctx;
    ProtoStats::Ptr stats_;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_CIPHER
