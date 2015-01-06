//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Pseudo-random number generator used for medium strength cryptographic
// items such as IVs but not keys.

#ifndef OPENVPN_RANDOM_PRNG_H
#define OPENVPN_RANDOM_PRNG_H

#include <cstring>
#include <algorithm>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/random/randapi.hpp>
#include <openvpn/crypto/digestapi.hpp>

namespace openvpn {

  class PRNG : public RandomAPI
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

    PRNG() : nonce_reseed_bytes(0), n_processed(0) {}

    PRNG(const char *digest_name,
	 const DigestFactory::Ptr& digest_factory,
	 const RandomAPI::Ptr& rng_arg,
	 const size_t nonce_secret_len,
	 const size_t nonce_reseed_bytes_arg = NONCE_DEFAULT_RESEED_BYTES)
      : nonce_reseed_bytes(0), n_processed(0)
    {
      init(digest_name, digest_factory, rng_arg, nonce_secret_len, nonce_reseed_bytes_arg);
    }

    void init(const char *digest_name,
	      const DigestFactory::Ptr& digest_factory,
	      const RandomAPI::Ptr& rng_arg,
	      const size_t nonce_secret_len,
	      const size_t nonce_reseed_bytes_arg = NONCE_DEFAULT_RESEED_BYTES)
    {
      if (nonce_secret_len < NONCE_SECRET_LEN_MIN || nonce_secret_len > NONCE_SECRET_LEN_MAX)
	throw prng_bad_nonce_len();

      DigestContext::Ptr dc = digest_factory->new_context(CryptoAlgs::lookup(digest_name));

      // allocate array for nonce and seed it
      nonce_t nd(dc->size() + nonce_secret_len, nonce_t::DESTRUCT_ZERO|nonce_t::ARRAY);
      reseed(nd, *rng_arg);

      // Move all items into *this as a last step to avoid
      // exceptions putting us in an inconsistent state.
      rng = rng_arg;
      digest_context = dc;
      nonce_reseed_bytes = nonce_reseed_bytes_arg;
      n_processed = 0;
      nonce_data.move(nd);
    }

    template <typename T>
    void rand_fill(T& obj)
    {
      rand_bytes(reinterpret_cast<unsigned char *>(&obj), sizeof(T));
    }

    // Random algorithm name
    virtual std::string name() const
    {
      return "PRNG/" + rng->name();
    }

    // Fill buffer with random bytes
    virtual void rand_bytes (unsigned char *output, size_t len)
    {
      if (digest_context)
	{
	  const size_t md_size = digest_context->size();
	  while (len > 0)
	    {
	      const size_t blen = std::min(len, md_size);
	      DigestInstance::Ptr digest(digest_context->new_digest());
	      digest->update(nonce_data.c_data(), nonce_data.size());
	      if (digest->final(nonce_data.data()) != md_size)
		throw prng_internal_error();
	      memcpy (output, nonce_data.data(), blen);
	      output += blen;
	      len -= blen;

	      // should we reseed?
	      if (nonce_reseed_bytes)
		{
		  n_processed += blen;
		  if (n_processed >= nonce_reseed_bytes)
		    {
		      reseed(nonce_data, *rng);
		      n_processed = 0;
		    }
		}
	    }
	}
      else
	rng->rand_bytes (output, len); // if init was not called, revert to rand_bytes
    }

    // Like rand_bytes, but don't throw exception.
    // Return true on successs, false on fail.
    virtual bool rand_bytes_noexcept(unsigned char *buf, size_t size)
    {
      try {
	rand_bytes(buf, size);
	return true;
      }
      catch (std::exception&)
	{
	  return false;
	}
    }

  private:
    static void reseed (nonce_t& nd, RandomAPI& rng)
    {
#if 1 /* Must be 1 for real usage */
      rng.rand_bytes(nd.data(), nd.size());
#else
#pragma message ( "WARNING: predictable PRNG sequence" )
      /* Only for testing -- will cause a predictable PRNG sequence */
      {
	for (size_t i = 0; i < nd.size(); ++i)
	  nd[i] = static_cast<unsigned char>(i);
      }
#endif
    }

    RandomAPI::Ptr rng;
    DigestContext::Ptr digest_context;
    size_t nonce_reseed_bytes;
    size_t n_processed;
    nonce_t nonce_data;
  };

} // namespace openvpn

#endif // OPENVPN_RANDOM_PRNG_H
