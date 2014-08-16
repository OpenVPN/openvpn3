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

#ifndef OPENVPN_SSL_SSLCHOOSE_H
#define OPENVPN_SSL_SSLCHOOSE_H

#ifdef USE_OPENSSL
#include <openvpn/openssl/crypto/api.hpp>
#include <openvpn/openssl/ssl/sslctx.hpp>
#include <openvpn/openssl/util/rand.hpp>
#endif

#ifdef USE_APPLE_SSL
#include <openvpn/applecrypto/crypto/api.hpp>
#include <openvpn/applecrypto/ssl/sslctx.hpp>
#include <openvpn/applecrypto/util/rand.hpp>
#endif

#ifdef USE_POLARSSL
#include <openvpn/polarssl/crypto/api.hpp>
#include <openvpn/polarssl/ssl/sslctx.hpp>
#include <openvpn/polarssl/util/rand.hpp>
#endif

#ifdef USE_POLARSSL_APPLE_HYBRID
#include <openvpn/applecrypto/crypto/api.hpp>
#include <openvpn/polarssl/ssl/sslctx.hpp>
#include <openvpn/applecrypto/util/rand.hpp>
#endif

namespace openvpn {
  namespace SSLLib {
#if defined(USE_POLARSSL)
    typedef PolarSSLCryptoAPI CryptoAPI;
    typedef PolarSSLContext<PolarSSLRandom> SSLAPI;
    typedef PolarSSLRandom RandomAPI;
#elif defined(USE_POLARSSL_APPLE_HYBRID)
    // Uses Apple framework for RandomAPI and CryptoAPI and PolarSSL for SSLAPI
    typedef AppleCryptoAPI CryptoAPI;
    typedef PolarSSLContext<AppleRandom> SSLAPI;
    typedef AppleRandom RandomAPI;
#elif defined(USE_APPLE_SSL)
    typedef AppleCryptoAPI CryptoAPI;
    typedef AppleSSLContext SSLAPI;
    typedef AppleRandom RandomAPI;
#elif defined(USE_OPENSSL)
    typedef OpenSSLCryptoAPI CryptoAPI;
    typedef OpenSSLContext SSLAPI;
    typedef OpenSSLRandom RandomAPI;
#else
#error no SSL library defined
#endif
  }
}

#endif
