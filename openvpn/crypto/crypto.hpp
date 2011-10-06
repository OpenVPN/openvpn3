#ifndef OPENVPN_CRYPTO_CRYPTO
#define OPENVPN_CRYPTO_CRYPTO

#include <openvpn/crypto/encrypt.hpp>
#include <openvpn/crypto/decrypt.hpp>

namespace openvpn {

  struct CryptoContext
  {
    Encrypt encrypt;
    Decrypt decrypt;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_CRYPTO
