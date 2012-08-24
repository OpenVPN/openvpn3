//
//  api.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_APPLECRYPTO_CRYPTO_API_H
#define OPENVPN_APPLECRYPTO_CRYPTO_API_H

#include <openvpn/applecrypto/crypto/cipher.hpp>
#include <openvpn/applecrypto/crypto/digest.hpp>
#include <openvpn/applecrypto/crypto/hmac.hpp>

namespace openvpn {

  // type container for Apple Crypto-level API
  struct AppleCryptoAPI {
    // cipher
    typedef AppleCrypto::Cipher Cipher;
    typedef AppleCrypto::CipherContext CipherContext;

    // digest
    typedef AppleCrypto::Digest Digest;
    typedef AppleCrypto::DigestContext DigestContext;

    // HMAC
    typedef AppleCrypto::HMACContext HMACContext;
  };
}

#endif
