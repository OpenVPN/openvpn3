#ifndef OPENVPN_RANDOM_PRNG_H
#define OPENVPN_RANDOM_PRNG_H

#include <cstring>
#include <algorithm>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/random/randbase.hpp>
#include <openvpn/gencrypto/evpdigest.hpp>

namespace openvpn {

  class PRNG : public RC<thread_unsafe_refcount>
  {
    typedef BufferAllocatedType<unsigned char> nonce_t;
  public:
    typedef boost::intrusive_ptr<PRNG> Ptr;

    enum {
      NONCE_SECRET_LEN_MIN = 16,
      NONCE_SECRET_LEN_MAX = 64,
      NONCE_DEFAULT_RESEED_BYTES = 4096
    };

    OPENVPN_SIMPLE_EXCEPTION(prng_bad_digest);
    OPENVPN_SIMPLE_EXCEPTION(prng_bad_nonce_len);
    OPENVPN_SIMPLE_EXCEPTION(prng_internal_error);

    PRNG() : nonce_md_(NULL), nonce_reseed_bytes_(0), n_processed_(0) {}

    PRNG(const char *digest,
	 const RandomBase::Ptr& rng_arg,
	 const size_t nonce_secret_len,
	 const size_t nonce_reseed_bytes = NONCE_DEFAULT_RESEED_BYTES)
    {
      init(digest, rng_arg, nonce_secret_len, nonce_reseed_bytes);
    }

    void init(const char *digest,
	      const RandomBase::Ptr& rng_arg,
	      const size_t nonce_secret_len,
	      const size_t nonce_reseed_bytes = NONCE_DEFAULT_RESEED_BYTES)
    {
      rng = rng_arg;
      if (nonce_secret_len < NONCE_SECRET_LEN_MIN || nonce_secret_len > NONCE_SECRET_LEN_MAX)
	throw prng_bad_nonce_len();
      const EVP_MD *md = EVP_get_digestbyname (digest);
      if (!md)
	throw prng_bad_digest();

      // allocate array for nonce and seed it
      nonce_t nd(EVP_MD_size(md) + nonce_secret_len, nonce_t::DESTRUCT_ZERO|nonce_t::ARRAY);
      reseed(nd);

      // Move all items into *this as a last step to avoid
      // exceptions putting us in an inconsistent state.
      n_processed_ = 0;
      nonce_reseed_bytes_ = nonce_reseed_bytes;
      nonce_md_ = md;
      nonce_data_.move(nd);
    }

    void
    bytes (unsigned char *output, size_t len)
    {
      if (nonce_md_)
	{
	  EVP_MD_CTX ctx;
	  const size_t md_size = EVP_MD_size (nonce_md_);
	  while (len > 0)
	    {
	      unsigned int outlen = 0;
	      const size_t blen = std::min(len, md_size);
	      EVP_DigestInit (&ctx, nonce_md_);
	      EVP_DigestUpdate (&ctx, nonce_data_.c_data(), nonce_data_.size());
	      EVP_DigestFinal (&ctx, nonce_data_.data(), &outlen);
	      EVP_MD_CTX_cleanup (&ctx);
	      if (outlen != md_size)
		throw prng_internal_error();
	      memcpy (output, nonce_data_.data(), blen);
	      output += blen;
	      len -= blen;

	      // should we reseed?
	      if (nonce_reseed_bytes_)
		{
		  n_processed_ += blen;
		  if (n_processed_ >= nonce_reseed_bytes_)
		    {
		      reseed(nonce_data_);
		      n_processed_ = 0;
		    }
		}
	    }
	}
      else
	rng->rand_bytes (output, len); // if init was not called, revert to rand_bytes
    }

  private:
    void reseed (nonce_t& nd)
    {
#if 1 /* Must be 1 for real usage */
      rng->rand_bytes(nd.data(), nd.size());
#else
#pragma message ( "WARNING: predictable PRNG sequence" )
      /* Only for testing -- will cause a predictable PRNG sequence */
      {
	for (size_t i = 0; i < nd.size(); ++i)
	  nd[i] = static_cast<unsigned char>(i);
      }
#endif
    }

    RandomBase::Ptr rng;
    const EVP_MD *nonce_md_;
    size_t nonce_reseed_bytes_;
    size_t n_processed_;
    nonce_t nonce_data_;
  };

} // namespace openvpn

#endif // OPENVPN_RANDOM_PRNG_H
