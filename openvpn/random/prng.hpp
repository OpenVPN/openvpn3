//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

namespace openvpn {

  template <typename RAND_API, typename CRYPTO_API>
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

    PRNG() : nonce_reseed_bytes(0), n_processed(0) {}

    PRNG(const char *digest,
	 const typename RAND_API::Ptr& rng_arg,
	 const size_t nonce_secret_len,
	 const size_t nonce_reseed_bytes_arg = NONCE_DEFAULT_RESEED_BYTES)
      : nonce_reseed_bytes(0), n_processed(0)
    {
      init(digest, rng_arg, nonce_secret_len, nonce_reseed_bytes_arg);
    }

    void init(const char *digest,
	      const typename RAND_API::Ptr& rng_arg,
	      const size_t nonce_secret_len,
	      const size_t nonce_reseed_bytes_arg = NONCE_DEFAULT_RESEED_BYTES)
    {
      if (nonce_secret_len < NONCE_SECRET_LEN_MIN || nonce_secret_len > NONCE_SECRET_LEN_MAX)
	throw prng_bad_nonce_len();

      typename CRYPTO_API::Digest md = typename CRYPTO_API::Digest(digest);

      // allocate array for nonce and seed it
      nonce_t nd(md.size() + nonce_secret_len, nonce_t::DESTRUCT_ZERO|nonce_t::ARRAY);
      reseed(nd, *rng_arg);

      // Move all items into *this as a last step to avoid
      // exceptions putting us in an inconsistent state.
      n_processed = 0;
      rng = rng_arg;
      nonce_reseed_bytes = nonce_reseed_bytes_arg;
      nonce_digest = md;
      nonce_data.move(nd);
    }

    void
    rand_bytes (unsigned char *output, size_t len)
    {
      if (nonce_digest.defined())
	{
	  const size_t md_size = nonce_digest.size();
	  while (len > 0)
	    {
	      const size_t blen = std::min(len, md_size);
	      typename CRYPTO_API::DigestContext ctx(nonce_digest);
	      ctx.update(nonce_data.c_data(), nonce_data.size());
	      if (ctx.final(nonce_data.data()) != md_size)
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

  private:
    static void reseed (nonce_t& nd, RAND_API& rng)
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

    typename RAND_API::Ptr rng;
    typename CRYPTO_API::Digest nonce_digest;
    size_t nonce_reseed_bytes;
    size_t n_processed;
    nonce_t nonce_data;
  };

} // namespace openvpn

#endif // OPENVPN_RANDOM_PRNG_H
