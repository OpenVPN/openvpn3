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

// Wrap the PolarSSL Cryptographic Random API defined in <polarssl/ctr_drbg.h>
// so that it can be used as the primary source of cryptographic entropy by
// the OpenVPN core.

#ifndef OPENVPN_POLARSSL_UTIL_RAND_H
#define OPENVPN_POLARSSL_UTIL_RAND_H

#include <polarssl/entropy_poll.h>
#include <polarssl/ctr_drbg.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>

namespace openvpn {

  class PolarSSLRandom : public RC<thread_unsafe_refcount> {
  public:
    OPENVPN_EXCEPTION(rand_error_polarssl);

    typedef boost::intrusive_ptr<PolarSSLRandom> Ptr;

    PolarSSLRandom()
    {
      if (ctr_drbg_init(&ctx, entropy_poll, NULL, NULL, 0) < 0)
	throw rand_error_polarssl("CTR_DRBG init");
    }

    const char *name() const {
      return "CTR_DRBG";
    }

    void rand_bytes(unsigned char *buf, const size_t size)
    {
      if (!rand_bytes_noexcept(buf, size))
	throw rand_error_polarssl("CTR_DRBG rand_bytes");
    }

    // Like rand_bytes, but don't throw exception.
    // Return true on successs, false on fail.
    bool rand_bytes_noexcept(unsigned char *buf, const size_t size)
    {
      return ctr_drbg_random(&ctx, buf, size) < 0 ? false : true;
    }

  private:
    static int entropy_poll(void *data, unsigned char *output, size_t len)
    {
      size_t olen;
      return platform_entropy_poll(data, output, len, &olen);
    }

    ctr_drbg_context ctx;
  };

}

#endif
