//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2022 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

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

    // must be called _before_ the server implementation starts threads; it guarantees
    // that all per thread instances get the same psid cookie hmac key
    static void pre_threading_setup()
    {
        get_key();
    }

    PsidCookieImpl(ServerProto::Factory *psfp)
        : pcfg_(*psfp->proto_context_config),
          not_tls_auth_mode_(!pcfg_.tls_auth_enabled()),
          now_(pcfg_.now), handwindow_(pcfg_.handshake_window),
          ta_hmac_recv_(pcfg_.tls_auth_context->new_obj()),
          ta_hmac_send_(pcfg_.tls_auth_context->new_obj())
    {
        if (not_tls_auth_mode_)
            return;

        // init tls_auth hmac (see ProtoContext.reset() case TLS_AUTH; also TLSAuthPreValidate ctor)
        if (pcfg_.key_direction >= 0)
        {
            // key-direction is 0 or 1
            const unsigned int key_dir = pcfg_.key_direction ? OpenVPNStaticKey::INVERSE : OpenVPNStaticKey::NORMAL;
            ta_hmac_send_->init(pcfg_.tls_key.slice(OpenVPNStaticKey::HMAC
                                                    | OpenVPNStaticKey::ENCRYPT | key_dir));
            ta_hmac_recv_->init(pcfg_.tls_key.slice(OpenVPNStaticKey::HMAC
                                                    | OpenVPNStaticKey::DECRYPT | key_dir));
        }
        else
        {
            // key-direction bidirectional mode
            ta_hmac_send_->init(pcfg_.tls_key.slice(OpenVPNStaticKey::HMAC));
            ta_hmac_recv_->init(pcfg_.tls_key.slice(OpenVPNStaticKey::HMAC));
        }

        // initialize psid HMAC context with digest type and key
        const StaticKey &key = get_key();
        hmac_ctx_.init(digest_, key.data(), key.size());
    }

    virtual ~PsidCookieImpl() = default;

    virtual Intercept intercept(ConstBuffer &pkt_buf, const PsidCookieAddrInfoBase &pcaib) override
    {
        // tls auth enabled is the only config we handle
        if (not_tls_auth_mode_)
        {                                       // test discovered in TLSAuthPreValidate
            return Intercept::DECLINE_HANDLING; // let existing code handle these cases
        }

        if (!pkt_buf.size())
        {
            return Intercept::EARLY_DROP; // packet validation fails, no opcode
        }
        CookieHelper chelp(pkt_buf[0]);
        if (chelp.is_clients_initial_reset())
        {
            return process_clients_initial_reset(pkt_buf, pcaib);
        }
        else if (chelp.is_clients_server_reset_ack())
        {
            return process_clients_server_reset_ack(pkt_buf, pcaib);
        }

        // JMD_TODO: log failure?  Logging DDoS?
        return Intercept::EARLY_DROP; // bad op field
    }

    virtual ProtoSessionID get_cookie_psid() override
    {
        ProtoSessionID ret_val = cookie_psid_;
        cookie_psid_.reset();
        return ret_val;
    }

    virtual void provide_psid_cookie_transport(PsidCookieTransportBase::Ptr pctb) override
    {
        pctb_ = pctb;
    }

#ifndef UNIT_TEST
  private:
#endif
    using CookieHelper = ProtoContext::PsidCookieHelper;

    Intercept process_clients_initial_reset(ConstBuffer &pkt_buf, const PsidCookieAddrInfoBase &pcaib)
    {
        static const size_t hmac_size = ta_hmac_recv_->output_size();
        // ovpn_hmac_cmp checks for adequate pkt_buf.size()
        bool pkt_hmac_valid = ta_hmac_recv_->ovpn_hmac_cmp(pkt_buf.c_data(), pkt_buf.size(), 1 + SID_SIZE, hmac_size, long_pktid_size_);
        if (!pkt_hmac_valid)
        {
            // JMD_TODO: log failure?  Logging DDoS?
            return Intercept::DROP_1ST;
        }

        // check for adequate packet size to complete this function
        static const size_t reqd_packet_size
            // clang-format off
            // [op_field] [cli_psid] [HMAC]      [cli_auth_pktid]   [cli_pktid]
            =  1 +        SID_SIZE + hmac_size + long_pktid_size_ + short_pktid_size_;
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
        PacketID cli_auth_pktid; // a.k.a, replay_packet_id in draft RFC
        cli_auth_pktid.read(recv_buf_copy, PacketID::LONG_FORM);
        PacketID cli_pktid; // a.k.a., packet_id in draft RFC
        cli_pktid.read(recv_buf_copy, PacketID::SHORT_FORM);

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
        const id_t cli_net_id = htonl(cli_pktid.id);
        send_buf.prepend((unsigned char *)&cli_net_id, sizeof(cli_net_id));
        send_buf.push_front((unsigned char)1);

        // gen head
        PacketIDSend svr_auth_pid(PacketID::LONG_FORM);
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
        ta_hmac_send_->ovpn_hmac_gen(send_buf.data(), send_buf.size(), 1 + SID_SIZE, ta_hmac_send_->output_size(), long_pktid_size_);

        // consumer's implementation to send the SERVER_HARD_RESET to the client
        bool send_ok = pctb_->psid_cookie_send_const(send_buf, pcaib);
        if (send_ok)
        {
            return Intercept::HANDLE_1ST;
        }

        return Intercept::DROP_1ST;
    }

    Intercept process_clients_server_reset_ack(ConstBuffer &pkt_buf, const PsidCookieAddrInfoBase &pcaib)
    {
        static const size_t hmac_size = ta_hmac_recv_->output_size();
        // ovpn_hmac_cmp checks for adequate pkt_buf.size()
        bool pkt_hmac_valid = ta_hmac_recv_->ovpn_hmac_cmp(pkt_buf.c_data(), pkt_buf.size(), 1 + SID_SIZE, hmac_size, long_pktid_size_);
        if (!pkt_hmac_valid)
        {
            // JMD_TODO: log failure?  Logging DDoS?
            return Intercept::DROP_2ND;
        }

        static const size_t reqd_packet_size
            // clang-format off
            // [op_field] [cli_psid] [HMAC]      [cli_auth_pktid]   [acked] [srv_psid] [cli_pktid]
            =  1 +        SID_SIZE + hmac_size + long_pktid_size_ + 5 +     SID_SIZE + short_pktid_size_;
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
        PacketID cli_auth_pktid; // a.k.a, replay_packet_id in draft RFC
        cli_auth_pktid.read(recv_buf_copy, PacketID::LONG_FORM);
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

    // key must be common to all threads
    static StaticKey create_key()
    {
        RandomAPI::Ptr rng(new SSLLib::RandomAPI(false));
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
        BufferAllocated hmac_result(SSLLib::CryptoAPI::HMACContext::MAX_HMAC_SIZE, 0);
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

    static constexpr CryptoAlgs::Type digest_ = CryptoAlgs::Type::SHA256;
    static constexpr size_t long_pktid_size_ = PacketID::size(PacketID::LONG_FORM);
    static constexpr size_t short_pktid_size_ = PacketID::size(PacketID::SHORT_FORM);

    const ProtoContext::ProtoConfig &pcfg_;
    bool not_tls_auth_mode_;
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
