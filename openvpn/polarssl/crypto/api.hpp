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

#ifndef OPENVPN_POLARSSL_CRYPTO_API_H
#define OPENVPN_POLARSSL_CRYPTO_API_H

#include <openvpn/polarssl/crypto/cipher.hpp>
#include <openvpn/polarssl/crypto/digest.hpp>
#include <openvpn/polarssl/crypto/hmac.hpp>

namespace openvpn {

  // type container for PolarSSL Crypto-level API
  struct PolarSSLCryptoAPI {
    // cipher
    typedef PolarSSLCrypto::Cipher Cipher;
    typedef PolarSSLCrypto::CipherContext CipherContext;

    // digest
    typedef PolarSSLCrypto::Digest Digest;
    typedef PolarSSLCrypto::DigestContext DigestContext;

    // HMAC
    typedef PolarSSLCrypto::HMACContext HMACContext;
  };
}

#endif
