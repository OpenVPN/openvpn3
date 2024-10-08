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

// Wrap the OpenSSL HMAC API defined in <openssl/hmac.h> so
// that it can be used as part of the crypto layer of the OpenVPN core.

#ifndef OPENVPN_OPENSSL_CRYPTO_HMAC_H
#define OPENVPN_OPENSSL_CRYPTO_HMAC_H

#include <string>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/openssl/crypto/digest.hpp>

#include <openvpn/openssl/compat.hpp>

namespace openvpn::OpenSSLCrypto {
class HMACContext
{
  public:
    HMACContext(const HMACContext &) = delete;
    HMACContext &operator=(const HMACContext &) = delete;

    HMACContext &operator=(HMACContext &&rhs)
    {
        erase();
        ctx = rhs.ctx;
        rhs.ctx = nullptr;
        return *this;
    }

    OPENVPN_SIMPLE_EXCEPTION(openssl_hmac_uninitialized);
    OPENVPN_EXCEPTION(openssl_hmac_error);

    enum
    {
        MAX_HMAC_SIZE = EVP_MAX_MD_SIZE
    };

    HMACContext() = default;

    HMACContext(const CryptoAlgs::Type digest, const unsigned char *key, const size_t key_size)
    {
        init(digest, key, key_size);
    }

    ~HMACContext()
    {
        erase();
    }

    void init(const CryptoAlgs::Type digest, const unsigned char *key, const size_t key_size)
    {
        erase();
        ctx = HMAC_CTX_new();
        if (!HMAC_Init_ex(ctx, key, int(key_size), DigestContext::digest_type(digest, nullptr), nullptr))
        {
            openssl_clear_error_stack();
            HMAC_CTX_free(ctx);
            ctx = nullptr;
            throw openssl_hmac_error("HMAC_Init_ex (init)");
        }
    }

    void reset()
    {
        check_initialized();
        if (!HMAC_Init_ex(ctx, nullptr, 0, nullptr, nullptr))
        {
            openssl_clear_error_stack();
            throw openssl_hmac_error("HMAC_Init_ex (reset)");
        }
    }

    void update(const unsigned char *in, const size_t size)
    {
        check_initialized();

        if (!HMAC_Update(ctx, in, int(size)))
        {
            openssl_clear_error_stack();
            throw openssl_hmac_error("HMAC_Update");
        }
    }

    size_t final(unsigned char *out)
    {
        check_initialized();
        unsigned int outlen;
        if (!HMAC_Final(ctx, out, &outlen))
        {
            openssl_clear_error_stack();
            throw openssl_hmac_error("HMAC_Final");
        }
        return outlen;
    }

    size_t size() const
    {
        check_initialized();
        return size_();
    }

    bool is_initialized() const
    {
        return ctx != nullptr;
    }

  private:
    void erase()
    {
        HMAC_CTX_free(ctx);
        ctx = nullptr;
    }

    size_t size_() const
    {
        return HMAC_size(ctx);
    }

    void check_initialized() const
    {
#ifdef OPENVPN_ENABLE_ASSERT
        if (!ctx)
            throw openssl_hmac_uninitialized();
#endif
    }

    HMAC_CTX *ctx = nullptr;
};
} // namespace openvpn::OpenSSLCrypto

#endif
