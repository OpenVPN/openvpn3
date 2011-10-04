#ifndef OPENVPN_CRYPTO_ENCRYPT
#define OPENVPN_CRYPTO_ENCRYPT

#include <openssl/objects.h>
#include <openssl/evp.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/cipher.hpp>
#include <openvpn/crypto/digest.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/packet_id.hpp>
#include <openvpn/openssl/prng.hpp>

namespace openvpn {
  class Encrypt {
  public:
    // Flags
    enum  {
      PACKET_ID_LONG_FORM = (1<<0)
    };

  private:
    StaticKey key_;
    Cipher cipher_;
    Digest digest_;
    packet_id::PacketIDSend pid_;
    PRNG prng_;
    unsigned int flags_;
  };
} // namespace openvpn

#endif // OPENVPN_CRYPTO_ENCRYPT
