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

// OpenVPN CBC/HMAC data channel

#ifndef OPENVPN_CRYPTO_CRYPTO_CHM_H
#define OPENVPN_CRYPTO_CRYPTO_CHM_H

#include <openvpn/crypto/encrypt_chm.hpp>
#include <openvpn/crypto/decrypt_chm.hpp>
#include <openvpn/crypto/cryptodc.hpp>
#include <openvpn/random/randapi.hpp>
#include <openvpn/ssl/sslapi.hpp>

namespace openvpn {

template <typename CRYPTO_API>
class CryptoCHM : public CryptoDCInstance
{
  public:
    typedef CryptoDCInstance Base;

    CryptoCHM(
        SSLLib::Ctx libctx_arg,
        CryptoDCSettingsData dc_settings_data,
        const Frame::Ptr &frame_arg,
        const SessionStats::Ptr &stats_arg,
        const StrongRandomAPI::Ptr &rng_arg)
        : dc_settings(dc_settings_data),
          frame(frame_arg),
          stats(stats_arg),
          rng(rng_arg),
          libctx(libctx_arg)
    {
        encrypt_.frame = frame;
        decrypt_.frame = frame;
        encrypt_.set_rng(rng);
    }

    // Encrypt/Decrypt

    /* returns true if packet ID is close to wrapping */
    bool encrypt(BufferAllocated &buf, const PacketID::time_t now, const unsigned char *op32) override
    {
        encrypt_.encrypt(buf, now);
        return encrypt_.pid_send.wrap_warning();
    }

    Error::Type decrypt(BufferAllocated &buf, const PacketID::time_t now, const unsigned char *op32) override
    {
        return decrypt_.decrypt(buf, now);
    }

    // Initialization

    void init_cipher(StaticKey &&encrypt_key,
                     StaticKey &&decrypt_key) override
    {
        encrypt_.cipher.init(libctx, dc_settings.cipher(), encrypt_key, CRYPTO_API::CipherContext::ENCRYPT);
        decrypt_.cipher.init(libctx, dc_settings.cipher(), decrypt_key, CRYPTO_API::CipherContext::DECRYPT);
    }

    void init_hmac(StaticKey &&encrypt_key,
                   StaticKey &&decrypt_key) override
    {
        encrypt_.hmac.init(dc_settings.digest(), encrypt_key);
        decrypt_.hmac.init(dc_settings.digest(), decrypt_key);
    }

    void init_pid(const int recv_mode,
                  const char *recv_name,
                  const int recv_unit,
                  const SessionStats::Ptr &recv_stats_arg) override
    {
        /* CBC encryption always uses short packet ID */
        auto pid_form = PacketID::SHORT_FORM;

        encrypt_.pid_send.init(pid_form);
        decrypt_.pid_recv.init(recv_mode, pid_form, recv_name, recv_unit, recv_stats_arg);
    }

    bool consider_compression(const CompressContext &comp_ctx) override
    {
        return true;
    }

    // Indicate whether or not cipher/digest is defined

    unsigned int defined() const override
    {
        unsigned int ret = CRYPTO_DEFINED;
        if (CryptoAlgs::defined(dc_settings.cipher()))
            ret |= CIPHER_DEFINED;
        if (CryptoAlgs::defined(dc_settings.digest()))
            ret |= HMAC_DEFINED;
        return ret;
    }

    // Rekeying

    void rekey(const typename Base::RekeyType type) override
    {
    }

  private:
    CryptoDCSettingsData dc_settings;
    Frame::Ptr frame;
    SessionStats::Ptr stats;
    StrongRandomAPI::Ptr rng;
    SSLLib::Ctx libctx;

    EncryptCHM<CRYPTO_API> encrypt_;
    DecryptCHM<CRYPTO_API> decrypt_;
};

template <typename CRYPTO_API>
class CryptoContextCHM : public CryptoDCContext
{
  public:
    typedef RCPtr<CryptoContextCHM> Ptr;

    CryptoContextCHM(
        SSLLib::Ctx libctx_arg,
        CryptoDCSettingsData dc_settings_arg,
        const Frame::Ptr &frame_arg,
        const SessionStats::Ptr &stats_arg,
        const StrongRandomAPI::Ptr &rng_arg)
        : CryptoDCContext(dc_settings_arg.key_derivation()),
          dc_settings(std::move(dc_settings_arg)),
          frame(frame_arg),
          stats(stats_arg),
          rng(rng_arg),
          libctx(libctx_arg)
    {
    }

    CryptoDCInstance::Ptr new_obj(const unsigned int key_id) override
    {
        /* The check if the data channel cipher is valid is moved here, so encap_overhead
         * can be called and calculated for the OCC strings even if we do not allow the cipher
         * to be actually used */
        return new CryptoCHM<CRYPTO_API>(libctx,
                                         dc_settings,
                                         frame,
                                         stats,
                                         rng);
    }

    // cipher/HMAC/key info
    CryptoDCSettingsData crypto_info() override
    {
        return dc_settings;
    }

    // Info for ProtoContext::link_mtu_adjust

    size_t encap_overhead() const override
    {
        return CryptoAlgs::size(dc_settings.digest()) +      // HMAC
               CryptoAlgs::iv_length(dc_settings.cipher()) + // Cipher IV
               CryptoAlgs::block_size(dc_settings.cipher()); // worst-case PKCS#7 padding expansion
    }

  private:
    CryptoDCSettingsData dc_settings;
    Frame::Ptr frame;
    SessionStats::Ptr stats;
    StrongRandomAPI::Ptr rng;
    SSLLib::Ctx libctx;
};
} // namespace openvpn

#endif
