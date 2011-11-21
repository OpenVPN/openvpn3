#ifndef OPENVPN_GENCRYPTO_EVPDIGEST_H
#define OPENVPN_GENCRYPTO_EVPDIGEST_H

#include <openvpn/gencrypto/applecrypto.hpp>
#ifdef OPENVPN_APPLE_CRYPTO
#include <openvpn/applecrypto/evpdigest.hpp>
#else
#include <openssl/evp.h>
#endif

#endif // OPENVPN_GENCRYPTO_EVPDIGEST_H
