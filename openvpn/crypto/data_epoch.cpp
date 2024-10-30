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

#include "data_epoch.hpp"

#include <cstdint>

#include <openvpn/crypto/digestapi.hpp>
#include <openvpn/crypto/ovpnhmac.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/crypto/cryptochoose.hpp>

void openvpn::ovpn_hkdf_expand(const uint8_t *secret,
                               const uint8_t *info,
                               int info_len,
                               uint8_t *out,
                               int out_len)
{
    static constexpr int digest_size = 32;
    openvpn::DigestFactory::Ptr digest_factory(new openvpn::CryptoDigestFactory<openvpn::SSLLib::CryptoAPI>());

    auto hmac = digest_factory->new_hmac(openvpn::CryptoAlgs::SHA256, secret, 32);

    /* T(0) = empty string */
    uint8_t t_prev[digest_size];
    int t_prev_len = 0;

    for (uint8_t block = 1; (block - 1) * digest_size < out_len; block++)
    {
        hmac->reset();

        /* calculate T(block) */
        hmac->update(t_prev, t_prev_len);
        hmac->update(info, info_len);
        hmac->update(&block, 1);
        hmac->final(t_prev);

        t_prev_len = digest_size;

        /* Copy a full hmac output or remaining bytes */
        int out_offset = (block - 1) * digest_size;
        int copylen = std::min(digest_size, out_len - out_offset);

        std::memcpy(out + out_offset, t_prev, copylen);
    }
}

void openvpn::ovpn_expand_label(const uint8_t *secret, size_t secret_len, const uint8_t *label, size_t label_len, const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len)
{
    openvpn::DigestFactory::Ptr digest_factory(new openvpn::CryptoDigestFactory<openvpn::SSLLib::CryptoAPI>());

    if (secret_len != 32)
    {
        /* Our current implementation is not a general purpose one
         * and assume that the secret size matches the size of the
         * hash (SHA256) key */
        throw std::runtime_error("hkdf secret length mismatch");
    }

    /* 2 byte for the outlen encoded as uint16, 5 bytes for "ovpn ",
     * 1 byte for label length, 1 byte for context length */
    size_t prefix_len = 5;
    size_t hkdf_label_len = 2 + prefix_len + 1 + label_len + 1 + context_len;

    if (hkdf_label_len >= UINT16_MAX)
    {
        throw std::runtime_error("HKDF input parameters are too large");
    }

    openvpn::BufferAllocated hkdf_label{hkdf_label_len, 0};

    const std::uint16_t net_out_len = htons(static_cast<std::uint16_t>(out_len));
    hkdf_label.write((const unsigned char *)&net_out_len, sizeof(net_out_len));

    const std::uint8_t label_len_net = static_cast<std::uint8_t>(label_len + prefix_len);
    hkdf_label.write(&label_len_net, 1);
    hkdf_label.write("ovpn ", prefix_len);
    hkdf_label.write(label, label_len);
    const std::uint8_t context_len_net = static_cast<std::uint8_t>(context_len);
    if (context_len > 0)
    {
        hkdf_label.write(context, context_len);
    }
    hkdf_label.write(&context_len_net, 1);

    if (hkdf_label.length() != hkdf_label_len)
    {
        throw std::runtime_error("hkdf label length mismatch");
    }

    ovpn_hkdf_expand(secret, hkdf_label.c_data(), static_cast<int>(hkdf_label.length()), out, static_cast<uint16_t>(out_len));
}
