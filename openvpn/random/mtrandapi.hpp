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

// Non-cryptographic random number generator

#ifndef OPENVPN_RANDOM_MTRANDAPI_H
#define OPENVPN_RANDOM_MTRANDAPI_H

#include <random>

#include <openvpn/common/size.hpp>
#include <openvpn/random/randapi.hpp>

namespace openvpn {

  class MTRand : public RandomAPI
  {
  public:
    OPENVPN_EXCEPTION(mtrand_error);

    typedef RCPtr<MTRand> Ptr;

    MTRand(RandomAPI& seed)
      : rng(gen_seed(seed))
    {
    }

    MTRand()
      : rng(gen_seed())
    {
    }

    // Random algorithm name
    virtual std::string name() const
    {
      return "MTRand";
    }

    // Fill buffer with random bytes
    virtual void rand_bytes(unsigned char *buf, size_t size)
    {
      if (!rndbytes(buf, size))
	throw mtrand_error("rand_bytes failed");
    }

    // Like rand_bytes, but don't throw exception.
    // Return true on successs, false on fail.
    virtual bool rand_bytes_noexcept(unsigned char *buf, size_t size)
    {
      return rndbytes(buf, size);
    }

    std::mt19937_64::result_type rand()
    {
      return rng();
    }

  private:
    class ByteGenerator
    {
    public:
      static constexpr size_t SIZE = std::mt19937_64::word_size / 8;

      unsigned char get_byte(MTRand& mtr)
      {
	if (n_bytes == 0)
	  {
	    res.mt = mtr.rand();
	    n_bytes = SIZE;
	  }
	unsigned char ret = res.bytes[0];
	res.mt >>= 8;
	--n_bytes;
	return ret;
      }

    private:
      union Result {
	unsigned char bytes[SIZE];
	std::mt19937_64::result_type mt;
      };

      Result res;
      unsigned int n_bytes = 0;
    };

    bool rndbytes(unsigned char *buf, size_t size)
    {
      while (size--)
	*buf++ = bg.get_byte(*this);
      return true;
    }

    static std::mt19937_64::result_type gen_seed(RandomAPI& seed)
    {
      std::mt19937_64::result_type ret;
      seed.rand_fill(ret);
      return ret;
    }

    // Note: this is suboptimal because std::random_device returns
    // 32-bit value while std::mt19937_64 wants a 64-bit seed.
    static std::random_device::result_type gen_seed()
    {
      std::random_device rd;
      return rd();
    }

    std::mt19937_64 rng;
    ByteGenerator bg;
  };

}

#endif
