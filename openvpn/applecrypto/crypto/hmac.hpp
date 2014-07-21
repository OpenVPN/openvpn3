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

#ifndef OPENVPN_APPLECRYPTO_CRYPTO_HMAC_H
#define OPENVPN_APPLECRYPTO_CRYPTO_HMAC_H

// Wrap the Apple HMAC API defined in <CommonCrypto/CommonHMAC.h> so that
// it can be used as part of the crypto layer of the OpenVPN core.

#include <string>
#include <cstring>

#include <CommonCrypto/CommonHMAC.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/applecrypto/crypto/digest.hpp>

namespace openvpn {
  namespace AppleCrypto {
    class HMACContext : boost::noncopyable
    {
    public:
      OPENVPN_EXCEPTION(digest_cannot_be_used_with_hmac);
      OPENVPN_SIMPLE_EXCEPTION(hmac_uninitialized);
      OPENVPN_SIMPLE_EXCEPTION(hmac_keysize_error);

      enum {
	MAX_HMAC_SIZE = DigestContext::MAX_DIGEST_SIZE,
	MAX_HMAC_KEY_SIZE = 128,
      };

      HMACContext()
      {
	state = PRE;
      }

      HMACContext(const Digest& digest, const unsigned char *key, const size_t key_size)
      {
	init(digest, key, key_size);
      }

      ~HMACContext()
      {
      }

      void init(const Digest& digest, const unsigned char *key, const size_t key_size)
      {
	state = PRE;
	info = digest.get();
	alg = info->hmac_alg();
	if (alg == DigestInfo::NO_HMAC_ALG)
	  throw digest_cannot_be_used_with_hmac(info->name());
	if (key_size > MAX_HMAC_KEY_SIZE)
	  throw hmac_keysize_error();
	std::memcpy(key_, key, key_size_ = key_size);
	state = PARTIAL;
      }

      void reset() // Apple HMAC API is missing reset method, so we have to reinit
      {
	cond_reset(true);
      }

      void update(const unsigned char *in, const size_t size)
      {
	cond_reset(false);
	CCHmacUpdate(&ctx, in, size);
      }

      size_t final(unsigned char *out)
      {
	cond_reset(false);
	CCHmacFinal(&ctx, out);
	return info->size();
      }

      size_t size() const
      {
	if (!is_initialized())
	  throw hmac_uninitialized();
	return info->size();
      }

      bool is_initialized() const
      {
	return state >= PARTIAL;
      }

    private:
      void cond_reset(const bool force_init)
      {
	switch (state)
	  {
	  case PRE:
	    throw hmac_uninitialized();
	  case READY:
	    if (!force_init)
	      return;
	  case PARTIAL:
	    CCHmacInit(&ctx, alg, key_, key_size_);
	    state = READY;
	  }
      }

      enum State {
	PRE=0,
	PARTIAL,
	READY
      };
      int state;

      const DigestInfo *info;
      CCHmacAlgorithm alg;
      size_t key_size_;
      unsigned char key_[MAX_HMAC_KEY_SIZE];
      CCHmacContext ctx;
    };
  }
}

#endif
