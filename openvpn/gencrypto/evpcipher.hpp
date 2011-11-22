#ifndef OPENVPN_GENCRYPTO_EVPCIPHER_H
#define OPENVPN_GENCRYPTO_EVPCIPHER_H

#include <openvpn/gencrypto/applecrypto.hpp>
#ifdef OPENVPN_APPLE_CRYPTO
#include <openvpn/applecrypto/evpcipher.hpp>
#else
#include <openssl/objects.h>
#include <openssl/evp.h>
#endif

#endif // OPENVPN_GENCRYPTO_EVPCIPHER_H
