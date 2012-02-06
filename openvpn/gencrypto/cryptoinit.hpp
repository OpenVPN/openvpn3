#ifndef OPENVPN_GENCRYPTO_CRYPTOINIT_H
#define OPENVPN_GENCRYPTO_CRYPTOINIT_H

#ifdef USE_OPENSSL
#include <openvpn/openssl/util/init.hpp>
#endif

namespace openvpn {

  class crypto_init
  {
#if defined(USE_OPENSSL)
    openssl_init openssl_init_;
#endif    
  };

}

#endif // OPENVPN_GENCRYPTO_CRYPTOINIT_H
