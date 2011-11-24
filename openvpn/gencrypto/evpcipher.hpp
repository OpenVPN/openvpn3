#ifndef OPENVPN_GENCRYPTO_EVPCIPHER_H
#define OPENVPN_GENCRYPTO_EVPCIPHER_H

#include <openvpn/gencrypto/gencrypto.hpp>
#ifdef OPENVPN_APPLE_CRYPTO
#include <openvpn/applecrypto/crypto/evpcipher.hpp>
#else
#include <openssl/objects.h>
#include <openssl/evp.h>
#endif

#endif // OPENVPN_GENCRYPTO_EVPCIPHER_H
