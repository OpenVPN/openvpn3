#ifndef OPENVPN_CRYPTO_CRYPTO_H
#define OPENVPN_CRYPTO_CRYPTO_H

#include <openvpn/crypto/encrypt.hpp>
#include <openvpn/crypto/decrypt.hpp>

namespace openvpn {

  struct CryptoContext
  {
    Encrypt encrypt;
    Decrypt decrypt;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_CRYPTO_H
