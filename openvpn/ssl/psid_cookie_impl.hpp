//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2022- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

// A 64-bit protocol session ID, used by ProtoContext. But, unlike being random
// in psid.hpp, the PsidCookieImpl class derives it via an HMAC of information
// on the incoming client's OpenVPN HARD_RESET control message.  This creates a
// session id that acts like a syn-cookie on the OpenVPN startup 3-way
// handshake.

#pragma once

#include <openvpn/ssl/psid_cookie.hpp>

#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>

#include <openvpn/ssl/psid.hpp>
#include <openvpn/transport/server/transbase.hpp>
#include <openvpn/server/servproto.hpp>

#include <optional>

namespace openvpn {

/**
 * @brief Implements the PsidCookie interface
 *
 * This code currently only supports tls-auth. The approach can be applied with
 * minimal changes also to tls-crypt/no auth but requires more changes/protocol
 * changes and updated clients for the tls-crypt-v2 case.
 *
 * This class is not thread safe; it expects to be instantiated in each thread of a
 * multi-threaded server implementation.
 */
class PsidCookieImpl : public PsidCookie
{
  public:
    static constexpr int SID_SIZE = ProtoSessionID::SIZE;
    static constexpr int OPCODE_SIZE = 1;

    // must be called _before_ the server implementation starts threads; it guarantees
    // that all per thread instances get the same psid cookie hmac key
    static void pre_threading_setup()
    {
        get_key();
    }

    PsidCookieImpl(ServerProto::Factory *psfp)
        : pcfg_(*psfp->proto_context_config),
          now_(pcfg_.now), handwindow_(pcfg_.handshake_window)
    {
        if (pcfg_.tls_auth_enabled())
        {
            ta_hmac_recv_ = pcfg_.tls_auth_context->new_obj();
            ta_hmac_send_ = pcfg_.tls_auth_context->new_obj();

            // init tls_auth hmac (see ProtoContext.reset() case TLS_AUTH; also TLSAuthPreValidate ctor)
            if (pcfg_.key_direction >= 0)
            {
                // key-direction is 0 or 1
                const unsigned int key_dir = pcfg_.key_direction ? OpenVPNStaticKey::INVERSE : OpenVPNStaticKey::NORMAL;
                ta_hmac_send_->init(pcfg_.tls_auth_key.slice(OpenVPNStaticKey::HMAC
                                                             | OpenVPNStaticKey::ENCRYPT | key_dir));
                ta_hmac_recv_->init(pcfg_.tls_auth_key.slice(OpenVPNStaticKey::HMAC
                                                             | OpenVPNStaticKey::DECRYPT | key_dir));
            }
            else
            {
                // key-direction bidirectional mode
                ta_hmac_send_->init(pcfg_.tls_auth_key.slice(OpenVPNStaticKey::HMAC));
                ta_hmac_recv_->init(pcfg_.tls_auth_key.slice(OpenVPNStaticKey::HMAC));
            }
        }

        // initialize psid HMAC context with digest type and key
        const StaticKey &key = get_key();
        hmac_ctx_.init(digest_, key.data(), key.size());
    }

    Intercept intercept(Buffer &pkt_buf, const PsidCookieAddrInfoBase &pcaib) override
    {
        if (!pcfg_.tls_auth_enabled() && !pcfg_.tls_crypt_v2_enabled())
            return Intercept::DECLINE_HANDLING;

        if (!pkt_buf.size())
            return Intercept::EARLY_DROP; // packet validation fails, no opcode

        CookieHelper chelp(pkt_buf[0]);

        const bool is_tls_crypt_v2 = (chelp.is_tls_crypt_v2() && pcfg_.tls_crypt_v2_enabled());

        if (chelp.is_clients_initial_reset())
        {
            return is_tls_crypt_v2
                       ? process_clients_initial_reset_tls_crypt(pkt_buf, pcaib, chelp)
                       : process_clients_initial_reset_tls_auth(pkt_buf, pcaib);
        }
        else if (chelp.is_clients_server_reset_ack())
        {
            return is_tls_crypt_v2
                       ? process_clients_server_reset_ack_tls_crypt(pkt_buf, pcaib)
                       : process_clients_server_reset_ack_tls_auth(pkt_buf, pcaib);
        }

        // JMD_TODO: log failure?  Logging DDoS?
        return Intercept::EARLY_DROP; // bad op field
    }

    ProtoSessionID get_cookie_psid() override
    {
        ProtoSessionID ret_val = cookie_psid_;
        cookie_psid_.reset();
        return ret_val;
    }

    void provide_psid_cookie_transport(PsidCookieTransportBase::Ptr pctb) override
    {
        pctb_ = std::move(pctb);
    }

#ifndef UNIT_TEST
  private:
#endif
    using CookieHelper = ProtoContext::PsidCookieHelper;

    Intercept process_clients_initial_reset_tls_auth(ConstBuffer &pkt_buf, const PsidCookieAddrInfoBase &pcaib)
    {
        static const size_t hmac_size = ta_hmac_recv_->output_size();

        // ovpn_hmac_cmp checks for adequate pkt_buf.size()
        bool pkt_hmac_valid = ta_hmac_recv_->ovpn_hmac_cmp(pkt_buf.c_data(),
                                                           pkt_buf.size(),
                                                           OPCODE_SIZE + SID_SIZE,
                                                           hmac_size,
                                                           PacketIDControl::idsize);
        if (!pkt_hmac_valid)
        {
            // JMD_TODO: log failure?  Logging DDoS?
            return Intercept::DROP_1ST;
        }

        // check for adequate packet size to complete this function
        static const size_t reqd_packet_size
            // clang-format off
            // [op_field]    [cli_psid] [HMAC]      [cli_auth_pktid]          [cli_pktid]
            =  OPCODE_SIZE + SID_SIZE + hmac_size + PacketIDControl::idsize + reliable::id_size;
        // clang-format on
        if (pkt_buf.size() < reqd_packet_size)
        {
            // JMD_TODO: log failure?  Logging DDoS?
            return Intercept::DROP_1ST;
        }

        // "buf_copy" here uses the same underlying data, but has it's own offset; skip
        // past client's op_field.
        ConstBuffer recv_buf_copy(pkt_buf.c_data() + 1, pkt_buf.size() - 1, true);
        // decapsulate_tls_auth
        const ProtoSessionID cli_psid(recv_buf_copy);
        recv_buf_copy.advance(hmac_size);

        PacketIDControl cli_auth_pktid; // a.k.a, replay_packet_id in draft RFC
        cli_auth_pktid.read(recv_buf_copy);

        uint8_t cli_net_id[4]; // a.k.a., packet_id in draft RFC

        recv_buf_copy.read(cli_net_id, sizeof(cli_net_id));

        // start building the server reply HARD_RESET packet
        BufferAllocated send_buf;
        static const Frame &frame = *pcfg_.frame;
        frame.prepare(Frame::WRITE_SSL_INIT, send_buf);

        // set server packet id (a.k.a., msg seq no) which would come from the
        // reliability layer, if we had one
        const reliable::id_t net_id = 0; // no htonl(0) since result is 0
        send_buf.prepend(static_cast<const void *>(&net_id), sizeof(net_id));

        // prepend_dest_psid_and_acks
        cli_psid.prepend(send_buf);
        send_buf.prepend(cli_net_id, sizeof(cli_net_id));
        send_buf.push_front((unsigned char)1);

        // gen head
        PacketIDControlSend svr_auth_pid{};
        svr_auth_pid.write_next(send_buf, true, now_->seconds_since_epoch());
        // make space for tls-auth HMAC
        send_buf.prepend_alloc(ta_hmac_send_->output_size());
        // write source PSID
        const ProtoSessionID srv_psid = calculate_session_id_hmac(cli_psid, pcaib, 0);
        srv_psid.prepend(send_buf);
        // write opcode
        const unsigned char op_field = CookieHelper::get_server_hard_reset_opfield();
        send_buf.push_front(op_field);
        // write hmac
        ta_hmac_send_->ovpn_hmac_gen(send_buf.data(),
                                     send_buf.size(),
                                     OPCODE_SIZE + SID_SIZE,
                                     ta_hmac_send_->output_size(),
                                     PacketIDControl::idsize);

        // consumer's implementation to send the SERVER_HARD_RESET to the client
        bool send_ok = pctb_->psid_cookie_send_const(send_buf, pcaib);
        if (send_ok)
        {
            return Intercept::HANDLE_1ST;
        }

        return Intercept::DROP_1ST;
    }

    Intercept process_clients_server_reset_ack_tls_auth(ConstBuffer &pkt_buf, const PsidCookieAddrInfoBase &pcaib)
    {
        static const size_t hmac_size = ta_hmac_recv_->output_size();
        // ovpn_hmac_cmp checks for adequate pkt_buf.size()
        bool pkt_hmac_valid = ta_hmac_recv_->ovpn_hmac_cmp(pkt_buf.c_data(),
                                                           pkt_buf.size(),
                                                           OPCODE_SIZE + SID_SIZE,
                                                           hmac_size,
                                                           PacketIDControl::idsize);
        if (!pkt_hmac_valid)
        {
            // JMD_TODO: log failure?  Logging DDoS?
            return Intercept::DROP_2ND;
        }

        static const size_t reqd_packet_size
            // clang-format off
            // [op_field]    [cli_psid] [HMAC]      [cli_auth_pktid]         [acked] [srv_psid]
            =  OPCODE_SIZE + SID_SIZE + hmac_size + PacketIDControl::size() + 5 +    SID_SIZE;
        // the fixed size, 5, of the [acked] field recognizes that the client's first
        // response will ack exactly one packet, the server's HARD_RESET
        // clang-format on
        if (pkt_buf.size() < reqd_packet_size)
        {
            // JMD_TODO: log failure?  Logging DDoS?
            return Intercept::DROP_2ND;
        }

        // "buf_copy" here uses the same underlying data, but has it's own offset; skip
        // past client's op_field.
        ConstBuffer recv_buf_copy(pkt_buf.c_data() + 1, pkt_buf.size() - 1, true);
        // decapsulate_tls_auth
        const ProtoSessionID cli_psid(recv_buf_copy);
        recv_buf_copy.advance(hmac_size);

        PacketIDControl cli_auth_pktid; // a.k.a, replay_packet_id in draft RFC
        cli_auth_pktid.read(recv_buf_copy);

        unsigned int ack_count = recv_buf_copy[0];
        if (ack_count != 1)
        {
            return Intercept::DROP_2ND;
        }
        recv_buf_copy.advance(5);
        cookie_psid_.read(recv_buf_copy);

        // verify client's Psid Cookie
        bool is_cookie_valid = check_session_id_hmac(cookie_psid_, cli_psid, pcaib);
        if (is_cookie_valid)
        {
            return Intercept::HANDLE_2ND;
        }

        return Intercept::DROP_2ND;
    }

    Intercept process_clients_initial_reset_tls_crypt(Buffer &pkt_buf,
                                                      const PsidCookieAddrInfoBase &pcaib,
                                                      const CookieHelper &ch)
    {
        static const size_t hmac_size = pcfg_.tls_crypt_context->digest_size();

        ConstBuffer recv_buf_copy(pkt_buf.c_data() + 1, pkt_buf.size() - 1, true);

        ProtoSessionID client_session_id(recv_buf_copy);
        PacketIDControl replay_packet_id;
        replay_packet_id.read(recv_buf_copy);

        // This could be user-configurable so that we could just drop packets here if
        // we don't want to allow clients that don't support re-sending the WKc.
        if (!ch.supports_early_negotiation(replay_packet_id))
            return Intercept::DECLINE_HANDLING;

        auto pipes = init_tls_crypt_v2(pkt_buf);

        if (!pipes)
            return Intercept::DROP_1ST;

        auto [send, recv] = *pipes;

        // Create synthetic RESET packet payload.
        BufferAllocated payload;
        pcfg_.frame->prepare(Frame::WRITE_SSL_INIT, payload);

        CookieHelper::prepend_TLV(payload);

        PacketIDControl packet_id{0, 0};
        packet_id.write(payload, true);

        client_session_id.prepend(payload);

        const reliable::id_t acked_packet_id = 0;
        payload.prepend(&acked_packet_id, sizeof(acked_packet_id));
        payload.push_front((unsigned char)1);

        BufferAllocated work;
        // in 'work' we store all the fields that are not supposed to be encrypted
        pcfg_.frame->prepare(Frame::ENCRYPT_WORK, work);
        // make space for HMAC
        work.prepend_alloc(hmac_size);
        // write tls-crypt packet ID
        PacketIDControlSend svr_auth_pid;
        svr_auth_pid.write_next(work, true, now_->seconds_since_epoch());
        // write source PSID
        const ProtoSessionID srv_psid = calculate_session_id_hmac(client_session_id, pcaib, 0);
        srv_psid.prepend(work);
        // write opcode
        work.push_front(CookieHelper::get_server_hard_reset_opfield());

        // compute HMAC using header fields (from 'work') and plaintext
        // payload
        send->hmac_gen(work.data(), TLSCryptContext::hmac_offset, payload.c_data(), payload.size());

        const size_t data_offset = TLSCryptContext::hmac_offset + hmac_size;

        // encrypt the content of 'payload' (packet payload) into 'work'
        const size_t encrypt_bytes = send->encrypt(work.c_data() + TLSCryptContext::hmac_offset,
                                                   work.data() + data_offset,
                                                   work.max_size() - data_offset,
                                                   payload.c_data(),
                                                   payload.size());
        work.inc_size(encrypt_bytes);

        // consumer's implementation to send the SERVER_HARD_RESET to the client
        bool send_ok = pctb_->psid_cookie_send_const(work, pcaib);
        if (send_ok)
            return Intercept::HANDLE_1ST;

        return Intercept::DROP_1ST;
    }

    Intercept process_clients_server_reset_ack_tls_crypt(Buffer &pkt_buf, const PsidCookieAddrInfoBase &pcaib)
    {
        auto pipes = init_tls_crypt_v2(pkt_buf);

        if (!pipes)
            return Intercept::DROP_2ND;

        auto [send, recv] = *pipes;

        static const size_t hmac_size = pcfg_.tls_crypt_context->digest_size();

        const size_t head_size = OPCODE_SIZE + ProtoSessionID::SIZE + PacketIDControl::size();
        const unsigned char *orig_data = pkt_buf.c_data();

        ConstBuffer recv_buf_copy(pkt_buf.c_data() + 1, pkt_buf.size() - 1, true);

        ProtoSessionID client_session_id(recv_buf_copy);
        recv_buf_copy.advance(PacketIDControl::size() + hmac_size);

        BufferAllocated work;
        pcfg_.frame->prepare(Frame::DECRYPT_WORK, work);

        // Decrypt into `work`.
        const size_t decrypt_bytes = recv->decrypt(orig_data + head_size,
                                                   work.data(),
                                                   work.max_size(),
                                                   recv_buf_copy.c_data(),
                                                   recv_buf_copy.size());
        if (!decrypt_bytes)
            return Intercept::DROP_2ND;

        work.inc_size(decrypt_bytes);

        // Verify HMAC.
        if (!recv->hmac_cmp(orig_data, TLSCryptContext::hmac_offset, work.c_data(), work.size()))
            return Intercept::DROP_2ND;

        // We _should_ have one ACK (for the CONTROL_HARD_RESET_V2 previous message).
        if (work[0] != 1)
            return Intercept::DROP_2ND;

        // Discard the opcode and the acked packet ID.
        work.advance(OPCODE_SIZE + sizeof(uint32_t));

        // Retrieve the peer session ID (this must match).
        cookie_psid_.read(work);

        // verify client's Psid Cookie
        if (check_session_id_hmac(cookie_psid_, client_session_id, pcaib))
            return Intercept::HANDLE_2ND;

        return Intercept::DROP_2ND;
    }

    // key must be common to all threads
    static StaticKey create_key()
    {
        StrongRandomAPI::Ptr rng(new SSLLib::RandomAPI());
        const CryptoAlgs::Alg &alg = CryptoAlgs::get(digest_);

        // guarantee that the key is large enough
        StaticKey key;
        key.init_from_rng(*rng, alg.size());
        return key;
    }

    static const StaticKey &get_key()
    {
        static const StaticKey key = create_key();
        return key;
    }

    /**
     * @brief Calculate the psid cookie, the ProtoSessionID hmac
     *
     * @param cli_psid  Client's protocol session id, ProtoSessionID
     * @param pcaib  Client's address information, reproducibly hashable
     * @param offset  moves the time valid time window backward from current
     * @return ProtoSessionID  the psid cookie
     */
    ProtoSessionID calculate_session_id_hmac(const ProtoSessionID &cli_psid,
                                             const PsidCookieAddrInfoBase &pcaib,
                                             unsigned int offset)
    {
        hmac_ctx_.reset();

        // Get the time window for which the ProtoSessionID hmac is valid.  The window
        // size is an interval given by handwindow/2, one half of the configured
        // handshake timeout, typically 30 seconds.  The valid_time is the count of
        // intervals since the beginning of the epoch.  With offset zero, the valid_time
        // is the server's current interval; with offsets 1 to n, it is the server's nth
        // previous interval.
        //
        // There is the theoretical issue of valid_time wrapping after 2^32 intervals.
        // With 30 second intervals, around the year 4010.  Will not spoil my weekend.
        uint64_t interval = (handwindow_.raw() + 1) / 2;
        uint32_t valid_time = static_cast<uint32_t>(now_->raw() / interval - offset);
        // no endian concerns; hmac is created and checked by the same host
        hmac_ctx_.update(reinterpret_cast<const unsigned char *>(&valid_time),
                         sizeof(valid_time));

        // the memory slab at cli_addr_port of size cli_addrport_size is a reproducibly
        // hashable representation of the client's address and port
        size_t cli_addrport_size;
        const unsigned char *cli_addr_port = pcaib.get_abstract_cli_addrport(cli_addrport_size);
        hmac_ctx_.update(cli_addr_port, cli_addrport_size);

        // add session id of client
        const Buffer cli_psid_buf = cli_psid.get_buf();
        hmac_ctx_.update(cli_psid_buf.c_data(), SID_SIZE);

        // finalize the hmac and package it as the server's ProtoSessionID
        BufferAllocated hmac_result(SSLLib::CryptoAPI::HMACContext::MAX_HMAC_SIZE);
        ProtoSessionID srv_psid;
        hmac_ctx_.final(hmac_result.write_alloc(hmac_ctx_.size()));
        srv_psid.read(hmac_result);

        return srv_psid;
    }

    bool check_session_id_hmac(const ProtoSessionID &srv_psid,
                               const ProtoSessionID &cli_psid,
                               const PsidCookieAddrInfoBase &pcaib)
    {
        // check the current timestamp and the previous one in case the server's clock
        // has moved to the one following that given to the client
        for (unsigned int offset = 0; offset <= 1; ++offset)
        {
            ProtoSessionID calc_psid = calculate_session_id_hmac(cli_psid, pcaib, offset);

            if (srv_psid.match(calc_psid))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Set up a couple of TLSCryptInstance (send, recv) from a TLS crypt V2 packet's WKc
     *
     * @param  pkt_buf The packet holding the WKc at the end.
     * @return A pair of {send, recv} objects set up with the symmetric key. std::nullopt on error.
     */
    std::optional<std::pair<TLSCryptInstance::Ptr, TLSCryptInstance::Ptr>> init_tls_crypt_v2(Buffer &pkt_buf)
    {
        TLSCryptInstance::Ptr send;
        TLSCryptInstance::Ptr recv;

        TLSCryptInstance::Ptr tls_crypt_server = pcfg_.tls_crypt_context->new_obj_recv();

        if (ProtoContext::KeyContext::unwrap_tls_crypt_wkc(pkt_buf, pcfg_, *tls_crypt_server) != Error::SUCCESS)
            return std::nullopt;

        const unsigned int key_dir = pcfg_.ssl_factory->mode().is_server()
                                         ? OpenVPNStaticKey::NORMAL
                                         : OpenVPNStaticKey::INVERSE;

        send = pcfg_.tls_crypt_context->new_obj_send();
        recv = pcfg_.tls_crypt_context->new_obj_recv();

        send->init(pcfg_.ssl_factory->libctx(),
                   pcfg_.wrapped_tls_crypt_key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::ENCRYPT | key_dir),
                   pcfg_.wrapped_tls_crypt_key.slice(OpenVPNStaticKey::CIPHER | OpenVPNStaticKey::ENCRYPT | key_dir));

        recv->init(pcfg_.ssl_factory->libctx(),
                   pcfg_.wrapped_tls_crypt_key.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::DECRYPT | key_dir),
                   pcfg_.wrapped_tls_crypt_key.slice(OpenVPNStaticKey::CIPHER | OpenVPNStaticKey::DECRYPT | key_dir));

        return std::pair{send, recv};
    }

    static constexpr CryptoAlgs::Type digest_ = CryptoAlgs::Type::SHA256;

    ProtoContext::ProtoConfig &pcfg_;
    TimePtr now_;
    const Time::Duration &handwindow_;

    OvpnHMACInstance::Ptr ta_hmac_recv_;
    OvpnHMACInstance::Ptr ta_hmac_send_;

    // the psid cookie specific hmac object
    SSLLib::CryptoAPI::HMACContext hmac_ctx_;

    PsidCookieTransportBase::Ptr pctb_;
    ProtoSessionID cookie_psid_;
};

} // namespace openvpn
