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

// Crypto algorithms

#ifndef OPENVPN_CRYPTO_CRYPTOALGS_H
#define OPENVPN_CRYPTO_CRYPTOALGS_H

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>

namespace openvpn {
  namespace CryptoAlgs {

    OPENVPN_EXCEPTION(crypto_alg);
    OPENVPN_SIMPLE_EXCEPTION(crypto_alg_index);

    enum Type {
      NONE=0,

      // CBC ciphers
      AES_128_CBC,
      AES_192_CBC,
      AES_256_CBC,
      DES_CBC,
      DES_EDE3_CBC,
      BF_CBC,

      // AEAD ciphers
      AES_128_GCM,
      AES_192_GCM,
      AES_256_GCM,

      // digests
      MD4,
      MD5,
      SHA1,
      SHA224,
      SHA256,
      SHA384,
      SHA512,

      SIZE,
    };

    enum Mode {
      MODE_UNDEF=0,
      CBC_HMAC,
      AEAD,
    };

    enum AlgFlags {
      F_CIPHER=(1<<0),    // alg is a cipher
      F_DIGEST=(1<<1),    // alg is a digest
      F_ALLOW_DC=(1<<2),  // alg may be used in OpenVPN data channel
    };

    struct Alg
    {
      const char *name;
      unsigned int flags;
      Mode mode;
    };

    const Alg algs[] = { // NOTE: MUST be indexed by CryptoAlgs::Type (CONST GLOBAL)
      { "NONE", F_CIPHER|F_DIGEST|F_ALLOW_DC, CBC_HMAC },
      { "AES-128-CBC", F_CIPHER|F_ALLOW_DC, CBC_HMAC },
      { "AES-192-CBC", F_CIPHER|F_ALLOW_DC, CBC_HMAC },
      { "AES-256-CBC", F_CIPHER|F_ALLOW_DC, CBC_HMAC },
      { "DES-CBC", F_CIPHER|F_ALLOW_DC, CBC_HMAC },
      { "DES-EDE3-CBC", F_CIPHER|F_ALLOW_DC, CBC_HMAC },
      { "BF-CBC", F_CIPHER|F_ALLOW_DC, CBC_HMAC },
      { "AES-128-GCM", F_CIPHER|F_ALLOW_DC, AEAD },
      { "AES-192-GCM", F_CIPHER|F_ALLOW_DC, AEAD },
      { "AES-256-GCM", F_CIPHER|F_ALLOW_DC, AEAD },
      { "MD4", F_DIGEST, MODE_UNDEF },
      { "MD5", F_DIGEST|F_ALLOW_DC, MODE_UNDEF },
      { "SHA1", F_DIGEST|F_ALLOW_DC, MODE_UNDEF },
      { "SHA224", F_DIGEST|F_ALLOW_DC, MODE_UNDEF },
      { "SHA256", F_DIGEST|F_ALLOW_DC, MODE_UNDEF },
      { "SHA384", F_DIGEST|F_ALLOW_DC, MODE_UNDEF },
      { "SHA512", F_DIGEST|F_ALLOW_DC, MODE_UNDEF },
    };

    inline const Alg& get(const Type type)
    {
      const size_t i = static_cast<size_t>(type);
      if (i >= SIZE)
	throw crypto_alg_index();
      return algs[i];
    }

    inline Type lookup(const std::string& name)
    {
      for (size_t i = 0; i < SIZE; ++i)
	{
	  const Alg& alg = algs[i];
	  if (string::strcasecmp(name, alg.name) == 0)
	    return static_cast<Type>(i);
	}
      OPENVPN_THROW(crypto_alg, name << ": not found");
    }

    inline const char *name(const Type type)
    {
      return get(type).name;
    }

    inline const char *name(const Type type, const char *default_name)
    {
      if (type == NONE)
	return default_name;
      else
	return get(type).name;
    }

    inline Type legal_dc_cipher(const Type type)
    {
      const Alg& alg = get(type);
      if ((alg.flags & (F_CIPHER|F_ALLOW_DC)) != (F_CIPHER|F_ALLOW_DC))
	OPENVPN_THROW(crypto_alg, alg.name << ": bad cipher");
      return type;
    }

    inline Type legal_dc_digest(const Type type)
    {
      const Alg& alg = get(type);
      if ((alg.flags & (F_DIGEST|F_ALLOW_DC)) != (F_DIGEST|F_ALLOW_DC))
	OPENVPN_THROW(crypto_alg, alg.name << ": bad digest");
      return type;
    }
  }
}

#endif
