#ifndef OPENVPN_GENCRYPTO_EVPHMAC_H
#define OPENVPN_GENCRYPTO_EVPHMAC_H

#include <openvpn/gencrypto/gencrypto.hpp>
#ifdef OPENVPN_APPLE_CRYPTO
#include <openvpn/applecrypto/crypto/evphmac.hpp>
#else
#include <openssl/hmac.h>
#endif

#endif // OPENVPN_GENCRYPTO_EVPHMAC_H
