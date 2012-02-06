#ifndef OPENVPN_GENCRYPTO_EVPHMAC_H
#define OPENVPN_GENCRYPTO_EVPHMAC_H

#if defined(USE_OPENSSL)
#include <openssl/hmac.h>
#elif defined(USE_APPLE_SSL)
#include <openvpn/applecrypto/crypto/evphmac.hpp>
#else
#error no library available to provide EVP HMAC functionality
#endif

#endif // OPENVPN_GENCRYPTO_EVPHMAC_H
