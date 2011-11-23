#ifndef OPENVPN_GENCRYPTO_EVPDIGEST_H
#define OPENVPN_GENCRYPTO_EVPDIGEST_H

#include <openvpn/gencrypto/applecrypto.hpp>
#ifdef OPENVPN_APPLE_CRYPTO
#include <openvpn/applecrypto/crypto/evpdigest.hpp>
#else
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif

#endif // OPENVPN_GENCRYPTO_EVPDIGEST_H
