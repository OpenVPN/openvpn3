#ifndef OPENVPN_OPENSSL_CRYPTO_API_H
#define OPENVPN_OPENSSL_CRYPTO_API_H

#include <openvpn/openssl/crypto/cipher.hpp>
#include <openvpn/openssl/crypto/digest.hpp>
#include <openvpn/openssl/crypto/hmac.hpp>

namespace openvpn {

  // type container for OpenSSL Crypto API
  struct OpenSSLCryptoAPI {
    // cipher
    typedef OpenSSLCrypto::Cipher Cipher;
    typedef OpenSSLCrypto::CipherContext CipherContext;

    // digest
    typedef OpenSSLCrypto::Digest Digest;
    typedef OpenSSLCrypto::DigestContext DigestContext;

    // HMAC
    typedef OpenSSLCrypto::HMACContext HMACContext;
  };
}

#endif
