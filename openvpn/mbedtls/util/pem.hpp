//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2017- OpenVPN Technologies, Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception

// Wrap the mbedTLS PEM API defined in <mbedtls/pem.h> so
// that it can be used as part of the crypto layer of the OpenVPN core.

#ifndef OPENVPN_MBEDTLS_UTIL_PEM_H
#define OPENVPN_MBEDTLS_UTIL_PEM_H

#include <mbedtls/pem.h>

namespace openvpn {
class MbedTLSPEM
{
  public:
    static bool pem_encode(BufferAllocated &dst,
                           const unsigned char *src,
                           size_t src_len,
                           const std::string &key_name)
    {
        std::string header = "-----BEGIN " + key_name + "-----\n";
        std::string footer = "-----END " + key_name + "-----\n";
        size_t out_len = 0;

        int ret = mbedtls_pem_write_buffer(header.c_str(),
                                           footer.c_str(),
                                           src,
                                           src_len,
                                           dst.data(),
                                           dst.max_size(),
                                           &out_len);
        if (ret == 0)
            dst.set_size(out_len);
        else
        {
            char buf[128];
            mbedtls_strerror(ret, buf, 128);
            OPENVPN_LOG("mbedtls_pem_write_buffer error: " << buf);
        }

        return (ret == 0);
    }

    static bool pem_decode(BufferAllocated &dst,
                           const char *src,
                           size_t src_len,
                           const std::string &key_name)
    {
        std::string header = "-----BEGIN " + key_name + "-----";
        std::string footer = "-----END " + key_name + "-----";
        mbedtls_pem_context ctx = {};
        size_t out_len = 0;

        int ret = mbedtls_pem_read_buffer(&ctx,
                                          header.c_str(),
                                          footer.c_str(),
                                          (unsigned char *)src,
                                          nullptr,
                                          0,
                                          &out_len);
        if (ret == 0)
        {
            size_t buflen = 0;
            const uint8_t *bufptr = mbedtls_pem_get_buffer(&ctx, &buflen);
            dst.init(bufptr, buflen, BufAllocFlags::DESTRUCT_ZERO);
        }

        mbedtls_pem_free(&ctx);

        return (ret == 0);
    }
};
}; // namespace openvpn

#endif /* OPENVPN_MBEDTLS_UTIL_PEM_H */
