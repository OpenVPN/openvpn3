#ifndef OPENVPN_GENCRYPTO_EVPDIGEST_H
#define OPENVPN_GENCRYPTO_EVPDIGEST_H

#if defined(USE_OPENSSL)
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#elif defined(USE_APPLE_SSL)
#include <openvpn/applecrypto/crypto/evpdigest.hpp>
#else
#error no library available to provide EVP digest functionality
#endif

#endif // OPENVPN_GENCRYPTO_EVPDIGEST_H
