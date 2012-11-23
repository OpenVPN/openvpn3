//
//  crypto.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// A general purpose container for OpenVPN protocol encrypt and decrypt objects.

#ifndef OPENVPN_CRYPTO_CRYPTO_H
#define OPENVPN_CRYPTO_CRYPTO_H

#include <openvpn/crypto/encrypt.hpp>
#include <openvpn/crypto/decrypt.hpp>

namespace openvpn {

  template <typename RAND_API, typename CRYPTO_API>
  struct CryptoContext
  {
    Encrypt<RAND_API, CRYPTO_API> encrypt;
    Decrypt<CRYPTO_API> decrypt;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_CRYPTO_H
