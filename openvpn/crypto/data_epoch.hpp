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


#ifndef CRYPTO_DATA_EPOCH_H
#define CRYPTO_DATA_EPOCH_H

#include <cstdint>
#include <cstdio>

namespace openvpn {

/**
 * Implementation of the RFC5869 HKDF-Expand function with the following
 * restrictions
 *  - salt is always assumed to be zero length (ie not supported)
 *  - IKM (secret) is assumed to be always 32 bytes
 *  - HASH is always SHA256
 *
 *  @param secret   the input keying material (HMAC key)
 *  @param info     context and application specific information
 *  @param info_len length of the application specific information
 *  @param out      output keying material
 *  @param out_len  length of output keying material
 */
void ovpn_hkdf_expand(const uint8_t *secret,
                      const uint8_t *info,
                      int info_len,
                      uint8_t *out,
                      int out_len);

/**
 * Variant of the RFC 8446 TLS 1.3  HKDF-Expand-Label function with the
 * following differences/restrictions:
 *  - secret must 32 bytes in length
 *  - label prefix is "ovpn " instead of "tls13 "
 *  - HASH is always SHA256
 *
 * @param secret        Input secret
 * @param secret_len    length of the input secret
 * @param label         Label for the exported key material
 * @param label_len     length of the label
 * @param context       optional context
 * @param context_len   length of the context
 * @param out      output keying material
 * @param out_len  length of output keying material
 *
 * Note, this function accepts size_t parameter only to make using this function easier. All values must be
 * uin16_t or smaller.
 */
void ovpn_expand_label(const uint8_t *secret,
                       size_t secret_len,
                       const uint8_t *label,
                       size_t label_len,
                       const uint8_t *context,
                       size_t context_len,
                       uint8_t *out,
                       size_t out_len);


} // namespace openvpn
#endif // CRYPTO_DATA_EPOCH_H