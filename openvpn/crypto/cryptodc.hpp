//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2022 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Base class for OpenVPN data channel encryption/decryption

#ifndef OPENVPN_CRYPTO_CRYPTODC_H
#define OPENVPN_CRYPTO_CRYPTODC_H

#include <utility> // for std::move
#include <cstdint> // for std::uint32_t, etc.

#include <openvpn/common/exception.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/error/error.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/packet_id.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>
#include <openvpn/compress/compress.hpp>

namespace openvpn {

// Base class for encryption/decryption of data channel
class CryptoDCInstance : public RC<thread_unsafe_refcount>
{
  public:
    typedef RCPtr<CryptoDCInstance> Ptr;

    // Encrypt/Decrypt

    // returns true if packet ID is close to wrapping
    virtual bool encrypt(BufferAllocated &buf, const PacketID::time_t now, const unsigned char *op32) = 0;

    virtual Error::Type decrypt(BufferAllocated &buf, const PacketID::time_t now, const unsigned char *op32) = 0;

    // Initialization

    // return value of defined()
    enum
    {
        CIPHER_DEFINED = (1 << 0),               // may call init_cipher method
        HMAC_DEFINED = (1 << 1),                 // may call init_hmac method
        CRYPTO_DEFINED = (1 << 2),               // may call encrypt or decrypt methods
        EXPLICIT_EXIT_NOTIFY_DEFINED = (1 << 3), // may call explicit_exit_notify method
        LONG_IV_DEFINED = (1 << 4)
    };
    virtual unsigned int defined() const = 0;

    virtual void init_cipher(StaticKey &&encrypt_key,
                             StaticKey &&decrypt_key)
        = 0;

    virtual void init_hmac(StaticKey &&encrypt_key,
                           StaticKey &&decrypt_key)
        = 0;

    virtual void init_pid(const int recv_mode,
                          const char *recv_name,
                          const int recv_unit,
                          const SessionStats::Ptr &recv_stats_arg)
        = 0;

    virtual void init_remote_peer_id(const int remote_peer_id)
    {
    }

    virtual bool consider_compression(const CompressContext &comp_ctx) = 0;

    virtual void explicit_exit_notify()
    {
    }

    // Rekeying

    enum RekeyType
    {
        ACTIVATE_PRIMARY,
        ACTIVATE_PRIMARY_MOVE,
        NEW_SECONDARY,
        PRIMARY_SECONDARY_SWAP,
        DEACTIVATE_SECONDARY,
        DEACTIVATE_ALL,
    };

    virtual void rekey(const RekeyType type) = 0;
};

/** class that holds settings for a data channel encryption */
class CryptoDCSettingsData
{
  public:
    OPENVPN_SIMPLE_EXCEPTION(no_data_channel_factory);

    CryptoDCSettingsData() = default;

    void set_cipher(CryptoAlgs::Type cipher)
    {
        cipher_ = cipher;
    }

    void set_digest(CryptoAlgs::Type digest)
    {
        digest_ = digest;
    }

    void set_aead_tag_end(bool at_the_end)
    {
        aead_tag_at_the_end = at_the_end;
    }

    void set_64_bit_packet_id(bool use_64bit_packet_id)
    {
        pktcounter_64bit = use_64bit_packet_id;
    }

    CryptoAlgs::Type cipher() const
    {
        return cipher_;
    }

    /**
     *  Retrieve the digest configured for the data channel.
     *  If the configured data channel cipher does not use any
     *  additional digest, CryptoAlgs::NONE is returned.
     *
     * @return  Returns the cipher digest in use
     */
    CryptoAlgs::Type digest() const
    {
        return (CryptoAlgs::use_cipher_digest(cipher_) ? digest_ : CryptoAlgs::NONE);
    }

    bool use64bitPktCounter() const
    {
        return pktcounter_64bit;
    }

    bool aeadTagAtTheEnd() const
    {
        return aead_tag_at_the_end;
    }

    void set_key_derivation(CryptoAlgs::KeyDerivation method)
    {
        key_derivation_ = method;
    }

    CryptoAlgs::KeyDerivation key_derivation() const
    {
        return key_derivation_;
    }


  private:
    CryptoAlgs::Type cipher_ = CryptoAlgs::NONE;
    CryptoAlgs::Type digest_ = CryptoAlgs::NONE;
    CryptoAlgs::KeyDerivation key_derivation_ = CryptoAlgs::KeyDerivation::OPENVPN_PRF;
    bool pktcounter_64bit = false;
    bool aead_tag_at_the_end = false;
};

// Factory for CryptoDCInstance objects
class CryptoDCContext : public RC<thread_unsafe_refcount>
{
  public:
    explicit CryptoDCContext(const CryptoAlgs::KeyDerivation method)
        : key_derivation(method)
    {
    }

    typedef RCPtr<CryptoDCContext> Ptr;

    virtual CryptoDCInstance::Ptr new_obj(const unsigned int key_id) = 0;

    virtual CryptoDCSettingsData crypto_info() = 0;

    // Info for ProtoContext::link_mtu_adjust
    virtual size_t encap_overhead() const = 0;

  protected:
    CryptoAlgs::KeyDerivation key_derivation = CryptoAlgs::KeyDerivation::OPENVPN_PRF;
};

// Factory for CryptoDCContext objects
class CryptoDCFactory : public RC<thread_unsafe_refcount>
{
  public:
    typedef RCPtr<CryptoDCFactory> Ptr;

    virtual CryptoDCContext::Ptr new_obj(const CryptoDCSettingsData) = 0;
};


// Manage cipher/digest settings, DC factory, and DC context.
class CryptoDCSettings : public CryptoDCSettingsData
{
  public:
    OPENVPN_SIMPLE_EXCEPTION(no_data_channel_factory);

    CryptoDCSettings() = default;

    void set_factory(const CryptoDCFactory::Ptr &factory)
    {
        factory_ = factory;
        context_.reset();
        dirty = false;
    }

    void set_cipher(const CryptoAlgs::Type new_cipher)
    {
        if (new_cipher != cipher())
        {
            CryptoDCSettingsData::set_cipher(new_cipher);
            dirty = true;
        }
    }

    void set_digest(const CryptoAlgs::Type new_digest)
    {
        if (new_digest != digest())
        {
            CryptoDCSettingsData::set_digest(new_digest);
            dirty = true;
        }
    }

    void set_aead_tag_end(bool at_the_end)
    {
        if (at_the_end != aeadTagAtTheEnd())
        {
            CryptoDCSettingsData::set_aead_tag_end(at_the_end);
            dirty = true;
        }
    }

    void set_64_bit_packet_id(bool use_64bit_packet_id)
    {
        if (use_64bit_packet_id != use64bitPktCounter())
        {
            CryptoDCSettingsData::set_64_bit_packet_id(use_64bit_packet_id);
            dirty = true;
        }
    }

    CryptoDCContext &context()
    {
        if (!context_ || dirty)
        {
            if (!factory_)
                throw no_data_channel_factory();
            context_ = factory_->new_obj(*this);
            dirty = false;
        }
        return *context_;
    }

    void reset()
    {
        factory_.reset();
        context_.reset();
        dirty = false;
    }

    [[nodiscard]] CryptoDCFactory::Ptr factory() const
    {
        return factory_;
    }

  private:
    bool dirty = false;
    CryptoDCFactory::Ptr factory_;
    CryptoDCContext::Ptr context_;
};
} // namespace openvpn

#endif
