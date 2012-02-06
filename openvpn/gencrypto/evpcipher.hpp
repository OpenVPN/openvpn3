#ifndef OPENVPN_GENCRYPTO_EVPCIPHER_H
#define OPENVPN_GENCRYPTO_EVPCIPHER_H

#if defined(USE_OPENSSL)
#include <openssl/objects.h>
#include <openssl/evp.h>
#elif defined(USE_APPLE_SSL)
#include <openvpn/applecrypto/crypto/evpcipher.hpp>
#else
#error no library available to provide EVP cipher functionality
#endif

#endif // OPENVPN_GENCRYPTO_EVPCIPHER_H
