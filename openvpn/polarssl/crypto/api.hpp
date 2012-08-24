//
//  api.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
