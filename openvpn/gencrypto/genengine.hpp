#ifndef OPENVPN_GENCRYPTO_GENENGINE_H
#define OPENVPN_GENCRYPTO_GENENGINE_H

#include <string>

#if defined(USE_OPENSSL)
#include <openvpn/openssl/util/engine.hpp>
#endif

namespace openvpn {

  void setup_crypto_engine(const std::string& engine)
  {
#if defined(USE_OPENSSL)
    openssl_setup_engine(engine);
#endif
  }

} // namespace openvpn

#endif // OPENVPN_GENCRYPTO_GENENGINE_H
