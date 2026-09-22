//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//
//

#pragma once


#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#include <mbedtls/pem.h>

#if not defined(MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION)
#define MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION
#endif

#if not defined(MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE)
#define MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE MBEDTLS_X509_EXT_KEY_USAGE
#endif
