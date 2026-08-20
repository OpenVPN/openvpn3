//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2017-2018 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Classes for handling OpenVPN tls-crypt-v2 internals

#ifndef OPENVPN_CRYPTO_TLS_CRYPT_V2_H
#define OPENVPN_CRYPTO_TLS_CRYPT_V2_H

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/tls_crypt.hpp>
#include <openvpn/random/randapi.hpp>
#include <openvpn/ssl/sslchoose.hpp>

namespace openvpn {
constexpr static const char *tls_crypt_v2_server_key_name = "OpenVPN tls-crypt-v2 server key";
constexpr static const char *tls_crypt_v2_client_key_name = "OpenVPN tls-crypt-v2 client key";

/**
 * @brief Convert a pem_encode() output buffer into a std::string.
 *
 * The buffer holds exactly the bytes pem_encode() wrote, and the two SSL
 * backends disagree on what those are: OpenSSL emits no NUL terminator
 * (reading the buffer as a C string overruns the allocation), while mbedTLS
 * appends one and counts it in the buffer size. Consume the explicit length
 * and drop any trailing NUL so both backends yield the same PEM text.
 *
 * @param pem  Buffer filled by SSLLib::PEMAPI::pem_encode().
 * @return The PEM text, without a trailing NUL character.
 */
inline std::string tls_crypt_v2_pem_to_string(const BufferAllocated &pem)
{
    std::string text(reinterpret_cast<const char *>(pem.c_data()), pem.size());
    while (!text.empty() && text.back() == '\0')
        text.pop_back();
    return text;
}

class TLSCryptV2ServerKey
{
  public:
    OPENVPN_SIMPLE_EXCEPTION(tls_crypt_v2_server_key_parse_error);
    OPENVPN_SIMPLE_EXCEPTION(tls_crypt_v2_server_key_encode_error);
    OPENVPN_SIMPLE_EXCEPTION(tls_crypt_v2_server_key_bad_size);

    TLSCryptV2ServerKey()
        : key_size(128),
          key(key_size, BufAllocFlags::DESTRUCT_ZERO)
    {
    }

    bool defined() const
    {
        return key.defined();
    }

    void parse(const std::string &key_text)
    {
        if (!SSLLib::PEMAPI::pem_decode(key, key_text.c_str(), key_text.length(), tls_crypt_v2_server_key_name))
            throw tls_crypt_v2_server_key_parse_error();

        if (key.size() != key_size)
            throw tls_crypt_v2_server_key_bad_size();
    }

    /**
     * @brief Mint a fresh server key, replacing any key already held.
     *
     * A server key is nothing but @c key_size random bytes, which
     * unwrap_tls_crypt_wkc() slices into the HMAC half @c Ka and the cipher half
     * @c Ke. Nothing is derived from it and there is no structure to get wrong, so
     * the only requirement on a key is the strength of its source.
     *
     * @param rng  Strong random source for the key material.
     */
    void generate(StrongRandomAPI &rng)
    {
        key.init(key_size, BufAllocFlags::DESTRUCT_ZERO);
        rng.rand_bytes(key.write_alloc(key_size), key_size);
    }

    void extract_key(OpenVPNStaticKey &tls_key) const
    {
        std::memcpy(tls_key.raw_alloc(), key.c_data(), key_size);
    }

    std::string render() const
    {
        BufferAllocated data(32 + 2 * key.size());

        if (!SSLLib::PEMAPI::pem_encode(data, key.c_data(), key.size(), tls_crypt_v2_server_key_name))
            throw tls_crypt_v2_server_key_encode_error();

        return tls_crypt_v2_pem_to_string(data);
    }

  private:
    const size_t key_size;
    BufferAllocated key;
};


class TLSCryptV2ClientKey
{
  public:
    enum
    {
        WKC_MAX_SIZE = 1024, // bytes
    };

    OPENVPN_SIMPLE_EXCEPTION(tls_crypt_v2_client_key_parse_error);
    OPENVPN_SIMPLE_EXCEPTION(tls_crypt_v2_client_key_encode_error);
    OPENVPN_SIMPLE_EXCEPTION(tls_crypt_v2_client_key_bad_size);

    TLSCryptV2ClientKey() = delete;

    TLSCryptV2ClientKey(TLSCryptContext::Ptr context)
        : key_size(OpenVPNStaticKey::KEY_SIZE),
          tag_size(context->digest_size()),
          context_(std::move(context))
    {
    }

    bool defined() const
    {
        return key.defined() && wkc.defined();
    }

    void parse(const std::string &key_text)
    {
        BufferAllocated data(key_size + WKC_MAX_SIZE, BufAllocFlags::DESTRUCT_ZERO);

        if (!SSLLib::PEMAPI::pem_decode(data, key_text.c_str(), key_text.length(), tls_crypt_v2_client_key_name))
            throw tls_crypt_v2_client_key_parse_error();

        if (data.size() < (tag_size + key_size))
            throw tls_crypt_v2_client_key_bad_size();

        key.init(data.data(), key_size, BufAllocFlags::DESTRUCT_ZERO);
        wkc.init(data.data() + key_size, data.size() - key_size, BufAllocFlags::DESTRUCT_ZERO);
    }

    void extract_key(OpenVPNStaticKey &tls_key)
    {
        std::memcpy(tls_key.raw_alloc(), key.c_data(), key_size);
    }

    std::string render() const
    {
        BufferAllocated data(32 + 2 * (key.size() + wkc.size()));
        BufferAllocated in(key, BufAllocFlags::GROW);
        in.append(wkc);

        if (!SSLLib::PEMAPI::pem_encode(data, in.c_data(), in.size(), tls_crypt_v2_client_key_name))
            throw tls_crypt_v2_client_key_encode_error();

        return tls_crypt_v2_pem_to_string(data);
    }

    void extract_wkc(BufferAllocated &wkc_out) const
    {
        wkc_out = wkc;
    }

    /**
     * @brief Mint a fresh client key @c Kc and the WKc that carries it to a server.
     *
     * Replaces any key already held, so that render() emits a complete client key
     * file which a server holding @p server_key can unwrap.
     *
     * @param rng            Strong random source for @c Kc.
     * @param server_key     Server key to wrap under.
     * @param metadata       Metadata to embed; authenticated, but not interpreted
     *                       here. Empty for a WKc carrying none.
     * @param metadata_type  Type byte prefixed to a non-empty @p metadata: 0x00 for
     *                       opaque user metadata (what PG's CSV records use), 0x01
     *                       for the timestamp stock tls-crypt-v2-genkey emits.
     * @param key_id         Server key ID (@c K_id) naming @p server_key, or
     *                       @c std::nullopt for a server configured with a single key.
     * @param libctx         SSL library context for the wrapping instance.
     *
     * @throws tls_crypt_v2_client_key_bad_size if @p metadata pushes the WKc past
     *         WKC_MAX_SIZE.
     */
    void generate(StrongRandomAPI &rng,
                  const TLSCryptV2ServerKey &server_key,
                  const std::string &metadata,
                  const int metadata_type,
                  const std::optional<std::uint32_t> key_id,
                  SSLLib::Ctx libctx = nullptr)
    {
        key.init(key_size, BufAllocFlags::DESTRUCT_ZERO);
        rng.rand_bytes(key.write_alloc(key_size), key_size);

        wkc = wrap(*context_, server_key, key.c_data(), key_size, metadata, metadata_type, key_id, libctx);
    }

    /**
     * @brief Wrap client key material and metadata into a WKc.
     *
     * The inverse of ProtoContext's unwrap_tls_crypt_wkc(), and the only producer of
     * the wire format in this tree:
     *
     * @code
     *   len = len(WKc)                                (16-bit, network byte order)
     *   T   = HMAC-SHA256(Ka, len || K_id || Kc || metadata)
     *   IV  = 128 most significant bits of T
     *   WKc = T || AES-256-CTR(Ke, IV, Kc || metadata) || K_id || len
     * @endcode
     *
     * @c Ka and @c Ke are the HMAC and cipher halves of @p server_key.
     *
     * Separate from generate() for callers that hold @c Kc already: tests building
     * deliberately malformed WKc's, or a tool rewrapping an existing client key
     * under a second server key.
     *
     * @param context        tls-crypt context supplying the digest and cipher.
     * @param server_key     Server key to wrap under.
     * @param kc             Client key material to embed.
     * @param kc_size        Bytes of @p kc to embed. Anything but a test wants
     *                       OpenVPNStaticKey::KEY_SIZE: a server rejects a WKc
     *                       carrying less than a full key.
     * @param metadata       Metadata payload, or empty for a WKc carrying none.
     * @param metadata_type  Type byte prefixed to a non-empty @p metadata.
     * @param key_id         Server key ID (@c K_id), or @c std::nullopt to omit it.
     * @param libctx         SSL library context for the wrapping instance.
     * @return The WKc, ready to append to a client key file or a handshake packet.
     *
     * @throws tls_crypt_v2_client_key_bad_size if the WKc would exceed WKC_MAX_SIZE.
     */
    static BufferAllocated wrap(TLSCryptContext &context,
                                const TLSCryptV2ServerKey &server_key,
                                const unsigned char *kc,
                                const size_t kc_size,
                                const std::string &metadata,
                                const int metadata_type,
                                const std::optional<std::uint32_t> key_id,
                                SSLLib::Ctx libctx = nullptr)
    {
        const size_t hmac_size = context.digest_size();

        OpenVPNStaticKey server_key_material;
        server_key.extract_key(server_key_material);

        // a single key set, so sliced without direction or mode, as unwrap does
        TLSCryptInstance::Ptr wrapper = context.new_obj_send();
        wrapper->init(libctx,
                      server_key_material.slice(OpenVPNStaticKey::HMAC),
                      server_key_material.slice(OpenVPNStaticKey::CIPHER));

        // the encrypted part: Kc, then the metadata behind its type byte
        BufferAllocated inner(kc_size + 1 + metadata.size(), BufAllocFlags::GROW | BufAllocFlags::DESTRUCT_ZERO);
        inner.write(kc, kc_size);
        if (!metadata.empty())
        {
            inner.push_back(static_cast<unsigned char>(metadata_type));
            inner.write(metadata.c_str(), metadata.size());
        }

        const std::uint32_t k_id_be = htonl(key_id.value_or(0));
        const size_t k_id_size = key_id ? sizeof(k_id_be) : 0;

        // the trailing length counts itself, the tag, the ciphertext and K_id
        const size_t wkc_size = sizeof(std::uint16_t) + hmac_size + inner.size() + k_id_size;
        if (wkc_size > WKC_MAX_SIZE)
            throw tls_crypt_v2_client_key_bad_size();

        const std::uint16_t wkc_len = static_cast<std::uint16_t>(wkc_size);
        const std::uint16_t wkc_len_be = htons(wkc_len);

        // the tag covers the length prefix and K_id as well as the plaintext
        BufferAllocated hmac_input(sizeof(wkc_len_be) + k_id_size + inner.size(),
                                   BufAllocFlags::GROW | BufAllocFlags::DESTRUCT_ZERO);
        hmac_input.write(&wkc_len_be, sizeof(wkc_len_be));
        if (key_id)
            hmac_input.write(&k_id_be, sizeof(k_id_be));
        hmac_input.write(inner.c_data(), inner.size());

        BufferAllocated out(wkc_len, BufAllocFlags::GROW);
        unsigned char *tag = out.write_alloc(hmac_size);
        wrapper->hmac_gen(tag, 0, hmac_input.c_data(), hmac_input.size());

        // the tag doubles as the CTR IV, as on the server's decrypt
        const size_t ciphertext_bytes = wrapper->encrypt(tag,
                                                         out.data() + hmac_size,
                                                         out.max_size() - hmac_size,
                                                         inner.c_data(),
                                                         inner.size());
        out.inc_size(ciphertext_bytes);
        if (key_id)
            out.write(&k_id_be, sizeof(k_id_be));
        out.write(&wkc_len_be, sizeof(wkc_len_be));

        return out;
    }

  private:
    BufferAllocated key;
    BufferAllocated wkc;

    const size_t key_size;
    const size_t tag_size;

    //! The digest/cipher pair generate() wraps with.
    TLSCryptContext::Ptr context_;
};

// the user can extend the TLSCryptMetadata and the TLSCryptMetadataFactory
// classes to implement its own metadata verification method.
//
// default method is to *ignore* the metadata contained in the WKc sent by the client
class TLSCryptMetadata : public RC<thread_unsafe_refcount>
{
  public:
    using Ptr = RCPtr<TLSCryptMetadata>;

    // override this method with your own verification mechanism.
    //
    // If type is -1 it means that metadata is empty.
    //
    virtual bool verify(int type, Buffer &metadata) const
    {
        return true;
    }
};

// abstract class to be extended when creating other factories
class TLSCryptMetadataFactory : public RC<thread_unsafe_refcount>
{
  public:
    using Ptr = RCPtr<TLSCryptMetadataFactory>;

    virtual TLSCryptMetadata::Ptr new_obj() = 0;
};

// factory implementation for the basic verification method
class CryptoTLSCryptMetadataFactory : public TLSCryptMetadataFactory
{
  public:
    TLSCryptMetadata::Ptr new_obj()
    {
        return new TLSCryptMetadata();
    }
};
} // namespace openvpn

#endif /* OPENVPN_CRYPTO_TLS_CRYPT_V2_H */
