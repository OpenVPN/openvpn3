#include "test_common.hpp"

#include <cstring>

#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/ssl/psid_cookie_impl.hpp>

using namespace openvpn;


TEST(PsidCookie, Setup)
{
    PsidCookieImpl::pre_threading_setup();

    ASSERT_TRUE(true);
}

// The following uland_addr46 type is a userland adaptation of an unpublished
// ovpn_addr46 type from James Yonan's kernel work.  The main idea is to create
// a reliably hashable representation of an IP address, be it IPv4 or IPv6
/* Discriminated union for IPv4/v6 addresses that should replace
   ovpn_addr.  The advantage of this approach over ovpn_addr is
   better alignment/packing and potential use as an rhashtable key. */
union uland_addr46 {
    /* IPv4 */
    struct
    {
        /* treat as IPv4-mapped IPv6 addresses */
        uint64_t a4_pre64; /* 0 */
        uint32_t a4_pre32; /* htonl(0xFFFF) */
        struct in_addr a4; /* the IPv4 address */
    };

    /* IPv6 */
    struct in6_addr a6;
    uint64_t a6_64[2];
};

class ClientAddressMock : public PsidCookieAddrInfoBase
{
  public:
    ClientAddressMock(RandomAPI &prng)
    {
        prng.rand_fill(addrport_);
    }
    const unsigned char *get_abstract_cli_addrport(size_t &slab_size) const override
    {
        slab_size = slab_size_;
        return addrport_.c;
    }
    // unused for these tests
    const void *get_impl_info() const override
    {
        return nullptr;
    }

    virtual ~ClientAddressMock() = default;

  private:
    // the detail here is not used; the slab is just randomly filled with data for the
    // hmac; this segment is here to show the motivation for slab_size_
    static constexpr size_t slab_size_ = sizeof(union uland_addr46) + sizeof(std::uint16_t);
    union {
        unsigned char c[slab_size_];
        struct
        {
            union uland_addr46 oaddr46;
            std::uint16_t port;
        } s;
    } addrport_;
};

class PsidCookieTest : public testing::Test
{
    openvpn_io::io_context dummy_io_context;
    Time now;
    ProtoContext::ProtoConfig::Ptr pcfg;

  protected:
    //! the server factory each session's ProtoConfig is cloned from
    ServerProto::Factory::Ptr spf;

    PsidCookieTest()
        : dummy_io_context(1), pcfg(new ProtoContext::ProtoConfig())
    {
        const std::string tls_key_fn = UNITTEST_SOURCE_DIR "/input/psid_cookie_tls.key";
        pcfg->tls_auth_key.parse_from_file(tls_key_fn);
        pcfg->tls_auth_factory.reset(new CryptoOvpnHMACFactory<SSLLib::CryptoAPI>());
        pcfg->set_tls_auth_digest(CryptoAlgs::lookup("SHA256"));
        pcfg->now = &now;
        pcfg->handshake_window = Time::Duration::seconds(60);
        pcfg->key_direction = 0;
        pcfg->rng.reset(new SSLLib::RandomAPI());
        pcfg->prng.reset(new MTRand(2020303));

        spf.reset(new ServerProto::Factory(dummy_io_context, *pcfg));
        spf->proto_context_config = pcfg;

        pcookie_impl.reset(new PsidCookieImpl(spf.get()));
    }

    Time set_clock(Time setting)
    {
        now = setting;
        return setting;
    }

    Time advance_clock(uint64_t binary_ms)
    {
        now += Time::Duration::binary_ms(binary_ms);
        return now;
    }

    void SetUp() override
    {
    }

    void TearDown() override
    {
    }

    std::unique_ptr<PsidCookieImpl> pcookie_impl;
};


TEST_F(PsidCookieTest, CheckSetup)
{
    const PsidCookieImpl *pci_dut = pcookie_impl.get();
    ASSERT_NE(pci_dut, nullptr);

    // check test clock's equivalence to the PsidCookieImpl clock
    const Time start(set_clock(Time::now()));
    EXPECT_TRUE(start == *pci_dut->now_);

    // spot check other aspects of successful pci_dut creation
    EXPECT_TRUE(pci_dut->pcfg_.tls_auth_key.defined());
}

TEST_F(PsidCookieTest, ValidTime)
{
    PsidCookieImpl &pci_dut(*pcookie_impl.get());
    const ClientAddressMock cli_addr(*pci_dut.pcfg_.prng);
    ProtoSessionID cli_psid;
    ProtoSessionID srv_psid;
    // interval duplicates the computation in calculate_session_id_hmac()
    const uint64_t interval = (pci_dut.pcfg_.handshake_window.raw() + 1) / 2;
    bool hmac_ok;

    cli_psid.randomize(*pci_dut.pcfg_.rng);

    set_clock(Time::now());
    srv_psid = pci_dut.calculate_session_id_hmac(cli_psid, cli_addr, 0);

    // server is in the same interval in which it offered the hmac
    hmac_ok = pci_dut.check_session_id_hmac(srv_psid, cli_psid, cli_addr);
    EXPECT_TRUE(hmac_ok);

    advance_clock(interval);
    // server is in the next interval after which it offered the hmac
    hmac_ok = pci_dut.check_session_id_hmac(srv_psid, cli_psid, cli_addr);
    EXPECT_TRUE(hmac_ok);

    advance_clock(interval);
    // server is two intervals after which it offered the hmac
    hmac_ok = pci_dut.check_session_id_hmac(srv_psid, cli_psid, cli_addr);
    EXPECT_FALSE(hmac_ok);
}


// Tests that exercise PsidCookieImpl::intercept() against crafted third
// packets of the OpenVPN 3-way handshake (the client reply to the server's
// HARD_RESET).  The cookie code only ever sees this packet when no peer
// state exists yet, so it must positively identify the packet as the
// handshake-completing one before letting the caller create state.
class PsidCookieInterceptTest : public PsidCookieTest
{
  protected:
    // Build a complete third-packet (tls-auth path) suitable for intercept().
    // Each on-the-wire field is parameterized so that individual tests can
    // perturb exactly one field while leaving everything else valid.
    BufferAllocated build_third_packet_tls_auth(const ProtoSessionID &cli_psid,
                                                const ProtoSessionID &cookie_psid,
                                                std::uint32_t acked_pktid_be,
                                                std::uint32_t own_pktid_be,
                                                unsigned char ack_count,
                                                unsigned char op_field)
    {
        PsidCookieImpl &pci = *pcookie_impl;
        // The server validates the incoming HMAC with ta_hmac_recv_; with
        // pcfg_.key_direction == 0 that key differs from ta_hmac_send_'s, so
        // we must sign the synthetic client packet with the recv key here.
        const size_t hmac_size = pci.ta_hmac_recv_->output_size();

        BufferAllocated buf;
        buf.reset(/*headroom=*/256, /*capacity=*/512, BufAllocFlags::GROW);

        // Fields are prepended in reverse on-the-wire order, mirroring how
        // process_clients_initial_reset_tls_auth() builds the server reply.
        buf.prepend(&own_pktid_be, sizeof(own_pktid_be));
        cookie_psid.prepend(buf);
        buf.prepend(&acked_pktid_be, sizeof(acked_pktid_be));
        buf.push_front(ack_count);

        PacketIDControlSend pid;
        pid.write_next(buf, /*prepend=*/true, pci.now_->seconds_since_epoch());

        buf.prepend_alloc(hmac_size);
        cli_psid.prepend(buf);
        buf.push_front(op_field);

        pci.ta_hmac_recv_->ovpn_hmac_gen(buf.data(),
                                         buf.size(),
                                         PsidCookieImpl::OPCODE_SIZE + PsidCookieImpl::SID_SIZE,
                                         hmac_size,
                                         PacketIDControl::idsize);
        return buf;
    }

    struct Fixture
    {
        ClientAddressMock cli_addr;
        ProtoSessionID cli_psid;
        ProtoSessionID cookie_psid;
    };

    Fixture make_fixture()
    {
        PsidCookieImpl &pci = *pcookie_impl;
        set_clock(Time::now());

        Fixture f{ClientAddressMock(*pci.pcfg_.prng), {}, {}};
        f.cli_psid.randomize(*pci.pcfg_.rng);
        f.cookie_psid = pci.calculate_session_id_hmac(f.cli_psid, f.cli_addr, 0);
        return f;
    }
};

TEST_F(PsidCookieInterceptTest, ThirdPacketValid)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
    EXPECT_TRUE(pcookie_impl->get_cookie_psid().match(f.cookie_psid));
}

TEST_F(PsidCookieInterceptTest, ThirdPacketAcceptsAckedPktidOne)
{
    // Both acked-pktid 0 (default) and 1 are tolerated as part of the early
    // handshake; only > 1 is treated as mid-session.  This mirrors OpenVPN 2.
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/htonl(1),
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsAckedPktidAboveOne)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/htonl(2),
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketAcceptsOwnPktidOne)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/htonl(1),
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsOwnPktidAboveOne)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/htonl(2),
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsAckCountNotOne)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/2,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketAcceptsAckV1)
{
    // P_ACK_V1 has no own message-id on the wire; intercept() must accept
    // it and skip the message-id check.  The packet builder still writes 4
    // bytes for own_pktid into the buffer, but the validator's reqd_size is
    // 4 bytes shorter for ACK_V1 so those bytes are simply ignored.
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::ACK_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsNonZeroKeyId)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 1));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::EARLY_DROP);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsBadCookie)
{
    auto f = make_fixture();
    // Tamper with the cookie psid: still valid HMAC over the packet, but
    // the embedded server psid does not match what calculate_session_id_hmac
    // would produce for this client.
    ProtoSessionID bogus;
    bogus.randomize(*pcookie_impl->pcfg_.rng);

    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      bogus,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

TEST_F(PsidCookieInterceptTest, ThirdPacketRejectsBadHmac)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));
    // Flip a byte in the HMAC field (right after the opcode + own session id).
    pkt.data()[PsidCookieImpl::OPCODE_SIZE + PsidCookieImpl::SID_SIZE] ^= 0x01;

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
}

//! Records what unwrap_tls_crypt_wkc() handed the hook, and answers with @p accept
class MetadataRecorder : public TLSCryptMetadata
{
  public:
    explicit MetadataRecorder(bool accept)
        : accept_(accept)
    {
    }

    bool verify(int type, Buffer &metadata) const override
    {
        ++n_calls;
        type_seen = type;
        payload_seen = buf_to_string(metadata);
        return accept_;
    }

    mutable unsigned int n_calls = 0;
    mutable int type_seen = -2; //!< -1 would mean "WKc carried no metadata"
    mutable std::string payload_seen;

  private:
    const bool accept_; //!< what verify() returns
};

/**
 * @brief The hook an embedder installs, standing in for PG's
 *
 * Keeps the recorders it makes reachable from the test: @c n_created counts how many
 * records were put to the hook at all, which is what says whether a packet reached it that
 * should not have, and @c last holds the verdict and payload of the most recent one.
 */
class MetadataRecorderFactory : public TLSCryptMetadataFactory
{
  public:
    TLSCryptMetadata::Ptr new_obj() override
    {
        ++n_created;
        last = new MetadataRecorder(accept);
        return last;
    }

    bool accept = true; //!< verify() verdict handed to the recorders produced here
    unsigned int n_created = 0;
    RCPtr<MetadataRecorder> last;
};

/**
 * @brief Tests for the tls-crypt-v2 arm of intercept()
 *
 * The client's third packet (CONTROL_WKC_V1) carries the WKc, and unwrap_tls_crypt_wkc()
 * strips it there, so this is the only place its metadata can be parsed; the handler that
 * parsed the cookie layer judges it before a session exists.
 *
 * The server this configures holds a tls-auth key as well, which is what PG deploys and the
 * case reset_tls_wrap_mode() resolves to TLS_AUTH.
 */
class PsidCookieTlsCryptV2Test : public PsidCookieInterceptTest
{
  protected:
    PsidCookieTlsCryptV2Test()
    {
        ProtoContext::ProtoConfig &pcfg = pcookie_impl->pcfg_;

        // server key IDs, the way PG deploys it: the WKc names its server key by
        // K_id, loaded from tls_crypt_v2_serverkey_dir as <2 hex digits>/<K_id>.key
        pcfg.tls_crypt_factory.reset(new CryptoTLSCryptFactory<SSLLib::CryptoAPI>());
        pcfg.set_tls_crypt_algs();
        pcfg.tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V2;
        pcfg.tls_crypt_v2_serverkey_id = true;
        pcfg.tls_crypt_v2_serverkey_dir = UNITTEST_SOURCE_DIR "/../ssl";
        pcfg.frame = frame_init_simple(2048);

        // our own copy of that key, to wrap with; unwrap overwrites pcfg.tls_crypt_key
        server_key_.parse(read_text(UNITTEST_SOURCE_DIR "/../ssl/06/063FE634.key"));

        // The cookie code needs an ssl_factory for libctx() and, via mode(), for the
        // client key's direction. No handshake happens here, but a server-mode context
        // insists on a certificate.
        SSLLib::SSLAPI::Config::Ptr sslcfg(new SSLLib::SSLAPI::Config());
        sslcfg->set_mode(Mode(Mode::SERVER));
        sslcfg->set_frame(pcfg.frame);
        sslcfg->set_rng(pcfg.rng);
        sslcfg->load_ca(read_text(UNITTEST_SOURCE_DIR "/../ssl/ca.crt"), true);
        sslcfg->load_cert(read_text(UNITTEST_SOURCE_DIR "/../ssl/server.crt"));
        sslcfg->load_private_key(read_text(UNITTEST_SOURCE_DIR "/../ssl/server.key"));
        pcfg.ssl_factory = sslcfg->new_factory();

        meta_factory.reset(new MetadataRecorderFactory());
        pcfg.tls_crypt_metadata_factory = meta_factory;

        // only wanted by the tests below that drive a ProtoContext, which builds a
        // KeyContext, which wants somewhere to derive key material from and a protocol
        // to know whether it is reliable
        pcfg.tlsprf_factory.reset(new CryptoTLSPRFFactory<SSLLib::CryptoAPI>());
        pcfg.protocol = Protocol(Protocol::UDPv4);

        // Kc, the client key the WKc wraps. Kept as raw bytes to write into the
        // WKc plaintext, and mirrored into a static key to key the client-side
        // tls-crypt instance with the same material.
        pcfg.prng->rand_bytes(client_key_raw_, sizeof(client_key_raw_));
        std::memcpy(client_key_.raw_alloc(), client_key_raw_, sizeof(client_key_raw_));
    }

    /**
     * @brief Build the WKc a client appends to its handshake packets.
     *
     * @param metadata       Metadata payload; empty for a WKc carrying none.
     * @param metadata_type  Type byte prefixed to @p metadata: 0x00 for user metadata,
     *                       0x01 for the timestamp stock tls-crypt-v2-genkey emits.
     */
    BufferAllocated make_wkc(const std::string &metadata, int metadata_type = 0x00)
    {
        return wrap_wkc(client_key_raw_, metadata, metadata_type);
    }

    //! As make_wkc(), but wrapping @p kc_size bytes of @p kc instead of this client's key.
    //! A kc_size below KEY_SIZE builds a WKc no client should ever send: correctly tagged,
    //! and with less key inside than it takes to key anything.
    BufferAllocated wrap_wkc(const unsigned char *kc,
                             const std::string &metadata,
                             int metadata_type,
                             size_t kc_size = OpenVPNStaticKey::KEY_SIZE)
    {
        ProtoContext::ProtoConfig &pcfg = pcookie_impl->pcfg_;

        // A WKc names its server key by K_id only where the server looks keys up that way.
        const std::optional<std::uint32_t> k_id = pcfg.tls_crypt_v2_serverkey_id ? std::optional<std::uint32_t>(SERVER_KEY_ID)
                                                                                 : std::nullopt;

        return TLSCryptV2ClientKey::wrap(*pcfg.tls_crypt_context,
                                         server_key_,
                                         kc,
                                         kc_size,
                                         metadata,
                                         metadata_type,
                                         k_id,
                                         pcfg.ssl_factory->libctx());
    }

    /**
     * @brief Build the tls-crypt-v2 third packet of the 3-way handshake: a
     *        CONTROL_WKC_V1 wrapped with Kc, ACKing the server's HARD_RESET and
     *        echoing the cookie psid back, with the WKc appended.
     */
    BufferAllocated build_third_packet_tls_crypt_v2(const ProtoSessionID &cli_psid,
                                                    const ProtoSessionID &cookie_psid,
                                                    const BufferAllocated &wkc,
                                                    unsigned char op_field)
    {
        return wrap_third_packet(client_key_, cli_psid, cookie_psid, wkc, op_field, 0);
    }

    //! As build_third_packet_tls_crypt_v2(), but wrapping the frame with @p kc and
    //! numbering the message @p own_pktid_be rather than 0.
    BufferAllocated wrap_third_packet(const OpenVPNStaticKey &kc,
                                      const ProtoSessionID &cli_psid,
                                      const ProtoSessionID &cookie_psid,
                                      const BufferAllocated &wkc,
                                      unsigned char op_field,
                                      std::uint32_t own_pktid_be)
    {
        ProtoContext::ProtoConfig &pcfg = pcookie_impl->pcfg_;
        const size_t hmac_size = pcfg.tls_crypt_context->digest_size();

        // ENCRYPT|INVERSE, as a client slices it: the server's DECRYPT|NORMAL key set
        TLSCryptInstance::Ptr send = pcfg.tls_crypt_context->new_obj_send();
        send->init(pcfg.ssl_factory->libctx(),
                   kc.slice(OpenVPNStaticKey::HMAC | OpenVPNStaticKey::ENCRYPT | OpenVPNStaticKey::INVERSE),
                   kc.slice(OpenVPNStaticKey::CIPHER | OpenVPNStaticKey::ENCRYPT | OpenVPNStaticKey::INVERSE));

        // the layout validate_3whs_ack_payload() walks
        BufferAllocated payload;
        pcfg.frame->prepare(Frame::WRITE_SSL_INIT, payload);
        payload.push_back(1); // ACK count
        const std::uint32_t acked_pktid_be = 0;
        payload.write(&acked_pktid_be, sizeof(acked_pktid_be));
        cookie_psid.write(payload);
        payload.write(&own_pktid_be, sizeof(own_pktid_be));

        // header fields, prepended in reverse on-the-wire order
        BufferAllocated work;
        pcfg.frame->prepare(Frame::ENCRYPT_WORK, work);
        work.prepend_alloc(hmac_size);
        PacketIDControlSend pid;
        pid.write_next(work, /*prepend=*/true, pcookie_impl->now_->seconds_since_epoch());
        cli_psid.prepend(work);
        work.push_front(op_field);

        send->hmac_gen(work.data(), TLSCryptContext::hmac_offset, payload.c_data(), payload.size());

        const size_t data_offset = TLSCryptContext::hmac_offset + hmac_size;
        const size_t encrypt_bytes = send->encrypt(work.c_data() + TLSCryptContext::hmac_offset,
                                                   work.data() + data_offset,
                                                   work.max_size() - data_offset,
                                                   payload.c_data(),
                                                   payload.size());
        work.inc_size(encrypt_bytes);

        // the WKc rides at the very end of the packet, on the opcodes that carry one
        if (!wkc.empty())
            work.write(wkc.c_data(), wkc.size());

        return work;
    }

    /**
     * @brief The handshake packet a client of this server can forge for another's address
     *
     * The WKc is the attacker's own, so it unwraps under the server key like any other, and
     * the frame is wrapped with the very Kc that WKc carries, so it authenticates under the
     * key the session installs from it. Nothing in it is the victim's.
     */
    BufferAllocated build_foreign_third_packet(const ProtoSessionID &cookie_psid,
                                               std::uint32_t own_pktid_be = 0)
    {
        unsigned char kc_raw[OpenVPNStaticKey::KEY_SIZE];
        pcookie_impl->pcfg_.prng->rand_bytes(kc_raw, sizeof(kc_raw));
        OpenVPNStaticKey kc;
        std::memcpy(kc.raw_alloc(), kc_raw, sizeof(kc_raw));

        ProtoSessionID cli_psid;
        cli_psid.randomize(*pcookie_impl->pcfg_.rng);

        return wrap_third_packet(kc,
                                 cli_psid,
                                 cookie_psid,
                                 wrap_wkc(kc_raw, "v=1,type=external", 0x00),
                                 wkc_v1_op_field(),
                                 own_pktid_be);
    }

    /**
     * @brief Build the tls-crypt-v2 first handshake packet: a CONTROL_HARD_RESET_CLIENT_V3
     *        with the WKc behind the tls-crypt frame.
     *
     * The cookie layer answers this one without decrypting it, so only the cleartext fields
     * mean anything. What has to be exact is the geometry: on this opcode the unwrap expects
     * the WKc to begin where the frame ends.
     */
    BufferAllocated build_first_packet_tls_crypt_v2(const ProtoSessionID &cli_psid,
                                                    const BufferAllocated &wkc)
    {
        const size_t frame_size = ProtoContext::KeyContext::tls_crypt_frame_size(pcookie_impl->pcfg_);

        BufferAllocated pkt(frame_size + wkc.size(), BufAllocFlags::GROW);
        pkt.push_back(ProtoContext::op_compose(ProtoContext::CONTROL_HARD_RESET_CLIENT_V3, 0));
        cli_psid.write(pkt);

        // the packet id; its id field is what supports_early_negotiation() weighs
        const std::uint32_t early_neg_be = htonl(ProtoContext::EARLY_NEG_START);
        pkt.write(&early_neg_be, sizeof(early_neg_be));
        const std::uint32_t pid_time_be = 0;
        pkt.write(&pid_time_be, sizeof(pid_time_be));

        // the hmac and payload behind it, which this path does not look at
        while (pkt.size() < frame_size)
            pkt.push_back(0);

        pkt.write(wkc.c_data(), wkc.size());
        return pkt;
    }

    //! the opcode of the third packet, the one whose WKc keys the session behind it
    static unsigned char wkc_v1_op_field()
    {
        return ProtoContext::op_compose(ProtoContext::CONTROL_WKC_V1, 0);
    }

    //! the opcode of the packets that follow, which carry no WKc to key a session from
    static unsigned char control_v1_op_field()
    {
        return ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0);
    }

    //! K_id of test/ssl/06/063FE634.key, the server key the WKc names
    static constexpr std::uint32_t SERVER_KEY_ID = 0x063FE634;

    RCPtr<MetadataRecorderFactory> meta_factory;
    unsigned char client_key_raw_[OpenVPNStaticKey::KEY_SIZE];
    OpenVPNStaticKey client_key_;    //!< Kc, as the client keys its tls-crypt instance
    TLSCryptV2ServerKey server_key_; //!< Ka/Ke, used here to wrap the WKc
};

// The session created for this client strips the WKc itself, uniformly for this copy and
// the retransmissions that follow, so intercept() must hand the packet on as it arrived.
TEST_F(PsidCookieTlsCryptV2Test, ThirdPacketIsForwardedIntact)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    const size_t wire_size = pkt.size();
    const std::string wire = buf_to_string(pkt);

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    EXPECT_EQ(pkt.size(), wire_size);
    EXPECT_EQ(buf_to_string(pkt), wire);
    // ... and the session takes the WKc off it
    EXPECT_TRUE(ProtoContext::KeyContext::strip_resent_wkc(pkt, pcookie_impl->pcfg_));
    EXPECT_LT(pkt.size(), wire_size);
}

// Nothing travels: the cookie layer unwrapped a key to answer the packet with and threw
// it away, so the config every session is cloned from is as it was before the client
// showed up, and one client's handshake cannot furnish another's session.
TEST_F(PsidCookieTlsCryptV2Test, NothingIsLeftOnTheSharedConfig)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    // the shared config holds what it was configured with: the server key ID to look
    // WKc-wrapping keys up by, and no client's key
    EXPECT_TRUE(pcookie_impl->pcfg_.tls_crypt_v2_serverkey_id);
    EXPECT_FALSE(pcookie_impl->pcfg_.tls_crypt_key.defined());
    EXPECT_FALSE(spf->clone_proto_config()->tls_crypt_key.defined());
}

//! Stands in for the transport the cookie layer answers a first packet through.
class RecordingTransport : public PsidCookieTransportBase
{
  public:
    size_t n_sent = 0;

  private:
    bool psid_cookie_send_const(Buffer &send_buf, const PsidCookieAddrInfoBase &pcaib) override
    {
        ++n_sent;
        return true;
    }
};

//! A ProtoContext needs one of these; it counts what the session puts on the wire.
class NullProtoCallback : public ProtoContextCallbackInterface
{
  public:
    size_t n_sent = 0;

  private:
    void control_net_send(const Buffer &net_buf) override
    {
        ++n_sent;
    }
    void control_recv(BufferPtr &&app_bp) override
    {
    }
    bool supports_epoch_data() override
    {
        return false;
    }
    void active(bool primary) override
    {
    }
};

//! Names every error the session reports, so a test can say why a packet was dropped.
class RecordingStats : public SessionStats
{
  public:
    std::string names;

  private:
    void error(const size_t type, const std::string *text = nullptr) override
    {
        if (!names.empty())
            names += " ";
        names += Error::name(type);
    }
};

/**
 * @brief The session kotun.hpp creates once intercept() has returned HANDLE_2ND
 *
 * Stood up the way ServerProto::Session::start() does, with the psid the cookie layer
 * validated, and fed packets the way the transport feeds them.
 */
struct CookieSession
{
    NullProtoCallback cb;
    RCPtr<RecordingStats> rec{new RecordingStats()};
    SessionStats::Ptr stats{rec};
    ProtoContext proto;

    CookieSession(const ProtoContext::ProtoConfig::Ptr &cfg, const ProtoSessionID &cookie_psid)
        : proto(&cb, cfg, stats)
    {
        proto.reset(cookie_psid);
        proto.start(cookie_psid);
        proto.flush(true);
        cb.n_sent = 0; // count only what the packets below draw out
    }

    //! @return how many packets the session put on the wire in reply
    size_t recv(const BufferAllocated &pkt)
    {
        const size_t before = cb.n_sent;

        BufferPtr bp = BufferAllocatedRc::Create(pkt.c_data(), pkt.size(), BufAllocFlags::GROW);
        const ProtoContext::PacketType pt = proto.packet_type(*bp);
        if (pt.is_control())
            proto.control_net_recv(pt, std::move(bp));
        proto.flush(true);

        return cb.n_sent - before;
    }
};

// The point of the whole arrangement: the session keys its control channel off the WKc
// still riding on the packet it is handed, having been given no key by anyone. It accepts
// the packet, which it could only do with the right key, and answers it.
TEST_F(PsidCookieTlsCryptV2Test, SessionDerivesItsKeyFromTheWkcOnItsFirstPacket)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
    // the cookie layer unwrapped the WKc to answer the packet, and judged nothing
    ASSERT_EQ(meta_factory->n_created, 0u);

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    EXPECT_GT(session.recv(pkt), 0u);

    // One hook for the client, made where the record is judged and shown it once
    EXPECT_EQ(meta_factory->n_created, 1u);
    EXPECT_EQ(meta_factory->last->n_calls, 1u);
}

TEST_F(PsidCookieTlsCryptV2Test, ThirdPacketParsesWKcMetadata)
{
    auto f = make_fixture();
    const std::string metadata = "v=1,type=external,sn=04:e3,time=1750000000,tenant=acme";

    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc(metadata),
                                                          wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
    EXPECT_TRUE(pcookie_impl->get_cookie_psid().match(f.cookie_psid));

    // the record reaches the hook from the session's own unwrap of the same WKc, once
    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    ASSERT_GT(session.recv(pkt), 0u);

    ASSERT_EQ(meta_factory->n_created, 1u);
    ASSERT_TRUE(meta_factory->last);
    EXPECT_EQ(meta_factory->last->n_calls, 1u);
    EXPECT_EQ(meta_factory->last->type_seen, 0x00);
    EXPECT_EQ(meta_factory->last->payload_seen, metadata);
}

// A WKc that does not unwrap keys nothing, so the packet it rode in on is dropped rather
// than answered -- and the handshake is not left half-converted, see
// ProtoContext::KeyContext::tls_crypt_v2_wanted().
TEST_F(PsidCookieTlsCryptV2Test, SessionDropsAPacketWhoseWkcDoesNotUnwrap)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    // flip a bit in the WKc ciphertext, past the tls-crypt frame the session decapsulates
    pkt.data()[pkt.size() - 32] ^= 0x01;

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    EXPECT_EQ(session.recv(pkt), 0u);
}

/**
 * @brief A server with one tls-crypt-v2 key in its config for every client
 *
 * The other of the two deployments: no K_id on the wire, no key directory.
 */
class PsidCookieSingleServerKeyTest : public PsidCookieTlsCryptV2Test
{
  protected:
    PsidCookieSingleServerKeyTest()
    {
        ProtoContext::ProtoConfig &pcfg = pcookie_impl->pcfg_;
        pcfg.tls_crypt_v2_serverkey_id = false;
        pcfg.tls_crypt_v2_serverkey_dir.clear();
        server_key_.extract_key(pcfg.tls_crypt_key);
    }
};

// Keying the server context was the caller's job in this mode, and only
// ProtoContext::reset_tls_crypt_server() did it. The cookie layer hands over a context
// straight from new_obj_recv(), so the first client packet threw ovpn_tls_crypt_wrong_mode
// out of intercept() and into the embedder's packet loop.
TEST_F(PsidCookieSingleServerKeyTest, ThirdPacketUnwrapsWithNoServerKeyIdOnTheWire)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);
}

// ... and the session behind it keys itself from the same WKc, with no key directory to
// consult and no K_id to consult it with.
TEST_F(PsidCookieSingleServerKeyTest, SessionDerivesItsKeyWithNoServerKeyId)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    EXPECT_GT(session.recv(pkt), 0u);
    EXPECT_EQ(meta_factory->n_created, 1u);
}

// The client key is the one part of a WKc that has to be there, and the check for it counted
// the length prefix and the K_id along with it -- neither of which is key material, and both
// advanced past before the key is read. A WKc short by those six bytes passed the check,
// passed the tag comparison behind it, and underflowed the read. Only a holder of the server
// key can wrap one, so this is a key generator's mistake, but it arrives as an exception.
TEST_F(PsidCookieTlsCryptV2Test, WkcWrappingTooLittleKeyIsRejectedRatherThanThrown)
{
    auto f = make_fixture();

    // short by the 2-byte length prefix and the 4-byte K_id in front of the key
    const size_t short_kc = OpenVPNStaticKey::KEY_SIZE - sizeof(std::uint16_t) - sizeof(std::uint32_t);
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          wrap_wkc(client_key_raw_, "", 0x00, short_kc),
                                                          wkc_v1_op_field());

    PsidCookie::Intercept ret = PsidCookie::Intercept::HANDLE_2ND;
    ASSERT_NO_THROW(ret = pcookie_impl->intercept(pkt, f.cli_addr));
    EXPECT_NE(ret, PsidCookie::Intercept::HANDLE_2ND);

    // and the unwrap leaves its out parameter untouched, as it promises: raw_alloc() defines
    // the key before the read that fills it, so a throw there left behind a client key that
    // had never been unwrapped
    BufferAllocated again = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                            f.cookie_psid,
                                                            wrap_wkc(client_key_raw_, "", 0x00, short_kc),
                                                            wkc_v1_op_field());
    TLSCryptInstance::Ptr server = pcookie_impl->pcfg_.tls_crypt_context->new_obj_recv();
    ProtoContext::KeyContext::UnwrappedWkc unwrapped;
    EXPECT_NE(ProtoContext::KeyContext::unwrap_tls_crypt_wkc(again, pcookie_impl->pcfg_, *server, unwrapped),
              Error::SUCCESS);
    EXPECT_FALSE(unwrapped.client_key.defined());
}

// Answering the first packet means unwrapping the WKc on it, and the unwrap trims the WKc off
// the buffer it is handed -- so this returned the caller a packet shorter than the one it
// passed in. Nothing forwards this packet today; anything that did would hand on a packet
// with no WKc, and a session keyed from that can never key itself.
TEST_F(PsidCookieTlsCryptV2Test, FirstPacketIsLeftAsItArrived)
{
    RCPtr<RecordingTransport> transport(new RecordingTransport());
    pcookie_impl->provide_psid_cookie_transport(transport);

    auto f = make_fixture();
    BufferAllocated pkt = build_first_packet_tls_crypt_v2(f.cli_psid, make_wkc("v=1,type=external"));

    const size_t wire_size = pkt.size();
    const std::string wire = buf_to_string(pkt);

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_1ST);
    EXPECT_EQ(transport->n_sent, 1u);

    EXPECT_EQ(pkt.size(), wire_size);
    EXPECT_EQ(buf_to_string(pkt), wire);
}

/**
 * @brief A server holding a tls-crypt-v2 key and no tls-auth one
 *
 * Starts in TLS_CRYPT_V2, where the fixtures above hold both keys, start in TLS_AUTH and
 * convert.
 */
class PsidCookieTlsCryptV2OnlyTest : public PsidCookieTlsCryptV2Test
{
  protected:
    PsidCookieTlsCryptV2OnlyTest()
    {
        pcookie_impl->pcfg_.tls_auth_key.erase();
    }
};

// The first packet a pre-filtering embedder sees is the one the receive context is keyed
// from, so there is no key to check it with. Only CONTROL_HARD_RESET_CLIENT_V3 was exempt,
// not the CONTROL_WKC_V1 a psid cookie layer leaves the session to key itself from.
TEST_F(PsidCookieTlsCryptV2OnlyTest, ControlNetValidateAcceptsTheWkcBearingPacket)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);

    BufferPtr bp = BufferAllocatedRc::Create(pkt.c_data(), pkt.size(), BufAllocFlags::GROW);
    const ProtoContext::PacketType pt = session.proto.packet_type(*bp);
    ASSERT_TRUE(pt.is_control());
    EXPECT_TRUE(session.proto.control_net_validate(pt, *bp));

    // the pre-filter and the path it filters for have to agree
    EXPECT_GT(session.recv(pkt), 0u);
}

// The same packet on a server holding a tls-auth key as well -- what PG deploys. Such a
// session is still TLS_AUTH when the pre-filter runs, since only decapsulate() converts it,
// so the exemption has to be recognised in that arm too.
TEST_F(PsidCookieTlsCryptV2Test, ControlNetValidateAcceptsTheWkcBearingPacketOnATlsAuthServer)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    // the premise: this fixture keeps the tls-auth key
    ASSERT_TRUE(pcookie_impl->pcfg_.tls_auth_enabled());

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);

    BufferPtr bp = BufferAllocatedRc::Create(pkt.c_data(), pkt.size(), BufAllocFlags::GROW);
    const ProtoContext::PacketType pt = session.proto.packet_type(*bp);
    ASSERT_TRUE(pt.is_control());
    EXPECT_TRUE(session.proto.control_net_validate(pt, *bp));

    // the pre-filter and the path it filters for have to agree
    EXPECT_GT(session.recv(pkt), 0u);
}

// The exemption follows the opcode, not the mode: one carrying no WKc keys nothing and stays
// judged with the tls-auth key. Same packet as above but for its op field.
TEST_F(PsidCookieTlsCryptV2Test, ControlNetValidateStillJudgesNonWkcOpcodesOnATlsAuthServer)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          control_v1_op_field());

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);

    BufferPtr bp = BufferAllocatedRc::Create(pkt.c_data(), pkt.size(), BufAllocFlags::GROW);
    const ProtoContext::PacketType pt = session.proto.packet_type(*bp);
    ASSERT_TRUE(pt.is_control());

    // tls-crypt wrapped, so the tls-auth key cannot vouch for it -- and nothing exempts it
    EXPECT_FALSE(session.proto.control_net_validate(pt, *bp));
}

/**
 * @brief A tls-crypt v1 server: one key shared with every client, no tls-auth, no WKc
 *
 * TLS_CRYPT is the one mode whose pre-filter can be reached with no peer pinned yet.
 */
class TlsCryptV1SessionTest : public PsidCookieTlsCryptV2Test
{
  protected:
    TlsCryptV1SessionTest()
    {
        ProtoContext::ProtoConfig &pcfg = pcookie_impl->pcfg_;
        pcfg.tls_auth_key.erase();
        pcfg.tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::V1;
        pcfg.tls_crypt_v2_serverkey_id = false;
        pcfg.tls_crypt_v2_serverkey_dir.clear();
        server_key_.extract_key(shared_key_);
        pcfg.tls_crypt_key = shared_key_;
    }

    //! A CONTROL_V1 frame from @p cli_psid, wrapped with the shared key and echoing @p srv_psid
    BufferAllocated v1_packet(const ProtoSessionID &cli_psid, const ProtoSessionID &srv_psid)
    {
        return wrap_third_packet(shared_key_, cli_psid, srv_psid, BufferAllocated(), control_v1_op_field(), 0);
    }

    //! The one key a v1 server shares with every client, in the form both sides slice
    OpenVPNStaticKey shared_key_;
};

// A pre-filter's verdict must not depend on what it was handed before. It pinned the peer
// psid from whatever packet reached it first, outside accept_peer(), so a holder of the
// shared key could pin itself from a spoofed datagram and lock the real client out.
TEST_F(TlsCryptV1SessionTest, ControlNetValidateDoesNotPinThePeer)
{
    auto f = make_fixture();
    CookieSession session(spf->clone_proto_config(), f.cookie_psid);

    ProtoSessionID other_psid;
    other_psid.randomize(*pcookie_impl->pcfg_.rng);

    auto validate = [&](const BufferAllocated &pkt)
    {
        BufferPtr bp = BufferAllocatedRc::Create(pkt.c_data(), pkt.size(), BufAllocFlags::GROW);
        const ProtoContext::PacketType pt = session.proto.packet_type(*bp);
        return pt.is_control() && session.proto.control_net_validate(pt, *bp);
    };

    // whichever arrives first, both are packets the pre-filter has no peer to judge against
    EXPECT_TRUE(validate(v1_packet(other_psid, f.cookie_psid)));
    EXPECT_TRUE(validate(v1_packet(f.cli_psid, f.cookie_psid)));
}

/**
 * @brief A plain tls-auth server: no tls-crypt of either version
 *
 * Its pre-filter is validate_tls_auth().
 */
class TlsAuthSessionTest : public PsidCookieTlsCryptV2Test
{
  protected:
    TlsAuthSessionTest()
    {
        ProtoContext::ProtoConfig &pcfg = pcookie_impl->pcfg_;
        pcfg.tls_crypt_ = ProtoContext::ProtoConfig::TLSCrypt::None;
        pcfg.tls_crypt_key.erase();
        pcfg.tls_crypt_v2_serverkey_id = false;
        pcfg.tls_crypt_v2_serverkey_dir.clear();
    }
};

// match() is false against an undefined psid, so the pre-filter turned away every packet
// until a peer was pinned -- including the one that would have pinned it.
TEST_F(TlsAuthSessionTest, ControlNetValidateAcceptsAPacketBeforeAPeerIsPinned)
{
    auto f = make_fixture();
    CookieSession session(spf->clone_proto_config(), f.cookie_psid);

    BufferAllocated pkt = build_third_packet_tls_auth(f.cli_psid,
                                                      f.cookie_psid,
                                                      /*acked_pktid_be=*/0,
                                                      /*own_pktid_be=*/0,
                                                      /*ack_count=*/1,
                                                      ProtoContext::op_compose(ProtoContext::CONTROL_V1, 0));

    BufferPtr bp = BufferAllocatedRc::Create(pkt.c_data(), pkt.size(), BufAllocFlags::GROW);
    const ProtoContext::PacketType pt = session.proto.packet_type(*bp);
    ASSERT_TRUE(pt.is_control());
    EXPECT_TRUE(session.proto.control_net_validate(pt, *bp));
}

// intercept() turns away only an empty datagram, so every one whose first byte carries a
// CONTROL_HARD_RESET_CLIENT_V3 opcode reaches the tls-crypt arm -- which read a psid and a
// packet id off it before establishing there was that much packet. Two bytes from anywhere
// threw buffer_underflow out of intercept(). The tls-auth sibling has always checked.
TEST_F(PsidCookieTlsCryptV2Test, ShortInitialResetIsDroppedRatherThanThrown)
{
    auto f = make_fixture();

    for (size_t size = 1; size <= 96; ++size)
    {
        BufferAllocated pkt(size, BufAllocFlags::CONSTRUCT_ZERO);
        pkt.set_size(size);
        pkt.data()[0] = ProtoContext::op_compose(ProtoContext::CONTROL_HARD_RESET_CLIENT_V3, 0);

        // where there is room, claim early-negotiation support so the arm carries on into the
        // WKc unwrap instead of declining at the flag; both outcomes are wanted
        if (size >= 1 + ProtoSessionID::SIZE + sizeof(std::uint32_t))
        {
            const std::uint32_t early_neg_be = htonl(ProtoContext::EARLY_NEG_START);
            std::memcpy(pkt.data() + 1 + ProtoSessionID::SIZE, &early_neg_be, sizeof(early_neg_be));
        }

        PsidCookie::Intercept ret = PsidCookie::Intercept::HANDLE_2ND;
        ASSERT_NO_THROW(ret = pcookie_impl->intercept(pkt, f.cli_addr)) << "size " << size;
        EXPECT_NE(ret, PsidCookie::Intercept::HANDLE_2ND) << "size " << size;
    }
}

// A WKc that unwraps says only that this server issued the key inside it, which is true of
// every client's WKc -- so a packet that unwraps one and then fails to authenticate under
// it must leave no trace. Were its key kept, the genuine packet arriving next would find
// the session already keyed and be decrypted with a stranger's key.
TEST_F(PsidCookieTlsCryptV2Test, SessionKeepsNoKeyFromAPacketThatFailedToAuthenticate)
{
    auto f = make_fixture();
    BufferAllocated good = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                           f.cookie_psid,
                                                           make_wkc("v=1,type=external"),
                                                           wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(good, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    // What an off-path attacker spoofing this client's address can put together: a WKc of
    // its own, which unwraps under the server key like any other, on a frame it cannot
    // wrap with the key that WKc carries.
    unsigned char foreign_key_raw[OpenVPNStaticKey::KEY_SIZE];
    pcookie_impl->pcfg_.prng->rand_bytes(foreign_key_raw, sizeof(foreign_key_raw));
    BufferAllocated spoofed = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                              f.cookie_psid,
                                                              wrap_wkc(foreign_key_raw, "v=1,type=external", 0x00),
                                                              wkc_v1_op_field());

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    EXPECT_EQ(session.recv(spoofed), 0u);

    // one datagram, and the client can still connect
    EXPECT_GT(session.recv(good), 0u);
}

// Authenticating at the tls-crypt layer only says the sender holds the Kc it supplied its
// own WKc for, which every client of this server can do. So a packet rejected after that --
// here on the psid the cookie layer issued, which the sender cannot know -- must leave the
// peer unpinned. Pinned, it closes tls_crypt_v2_wanted()'s conversion window for good and
// the real client's packets are checked as tls-auth from then on.
TEST_F(PsidCookieTlsCryptV2Test, SessionKeepsNoPeerPsidFromAPacketThatFailedToAuthenticate)
{
    auto f = make_fixture();
    BufferAllocated good = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                           f.cookie_psid,
                                                           make_wkc("v=1,type=external"),
                                                           wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(good, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    ProtoSessionID bogus_cookie_psid;
    bogus_cookie_psid.randomize(*pcookie_impl->pcfg_.rng);

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    EXPECT_EQ(session.recv(build_foreign_third_packet(bogus_cookie_psid)), 0u);

    // one datagram, and the client can still connect
    EXPECT_GT(session.recv(good), 0u);
}

// The other side of that coin: a packet of the peer's own that yields no message must keep
// the key it unwrapped, because the packet after it need not carry a WKc to re-key from.
// Here the first packet is refused by the reliable receive window, and the CONTROL_V1 behind
// it has no WKc of its own -- it can only be read with the key the refused packet left.
TEST_F(PsidCookieTlsCryptV2Test, SessionKeepsTheKeyOfItsPeersPacketThatYieldedNoMessage)
{
    auto f = make_fixture();
    BufferAllocated good = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                           f.cookie_psid,
                                                           make_wkc("v=1,type=external"),
                                                           wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(good, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);

    // the client's own third packet, numbered far outside the reliable receive window
    session.recv(wrap_third_packet(client_key_,
                                   f.cli_psid,
                                   f.cookie_psid,
                                   make_wkc("v=1,type=external"),
                                   wkc_v1_op_field(),
                                   htonl(5000)));

    BufferAllocated no_wkc = wrap_third_packet(client_key_,
                                               f.cli_psid,
                                               f.cookie_psid,
                                               BufferAllocated(),
                                               control_v1_op_field(),
                                               0);
    session.rec->names.clear();
    session.recv(no_wkc);

    // CC_ERROR here would be the session finding no key at all, HMAC_ERROR a key that is
    // not this client's
    EXPECT_EQ(session.rec->names, "");
}

// The session's hook is its own: it judges the record whether or not a cookie layer ever
// saw the client, which is how a session reached over TCP -- kotcp.hpp creates those with
// no cookie layer at all -- comes by its verdict.
TEST_F(PsidCookieTlsCryptV2Test, SessionWithoutACookieLayerJudgesTheRecordItself)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    // the packet reaches the session without passing intercept() first
    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    EXPECT_GT(session.recv(pkt), 0u);

    EXPECT_EQ(meta_factory->n_created, 1u);
    EXPECT_EQ(meta_factory->last->n_calls, 1u);
}

// Unwrapping a WKc says this server issued it, not that the sender holds the Kc inside: a
// captured one unwraps just the same. The hook ran anyway, and since a failed packet leaves
// the session un-keyed, an unauthenticated sender could drive it again and again.
TEST_F(PsidCookieTlsCryptV2Test, UnauthenticatedWkcRunsNoMetadataHook)
{
    auto f = make_fixture();

    // a WKc this server unwraps, on a frame not wrapped with the Kc it carries
    unsigned char foreign_key_raw[OpenVPNStaticKey::KEY_SIZE];
    pcookie_impl->pcfg_.prng->rand_bytes(foreign_key_raw, sizeof(foreign_key_raw));
    BufferAllocated spoofed = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                              f.cookie_psid,
                                                              wrap_wkc(foreign_key_raw, "v=1,type=ATTACKER", 0x00),
                                                              wkc_v1_op_field());

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);

    EXPECT_EQ(session.recv(spoofed), 0u);
    EXPECT_EQ(meta_factory->n_created, 0u);

    // un-keyed again, so the second attempt judges no more than the first
    EXPECT_EQ(session.recv(spoofed), 0u);
    EXPECT_EQ(meta_factory->n_created, 0u);
    EXPECT_FALSE(meta_factory->last);

    // the real client still connects, its record seen once
    BufferAllocated good = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                           f.cookie_psid,
                                                           make_wkc("v=1,type=external"),
                                                           wkc_v1_op_field());
    EXPECT_GT(session.recv(good), 0u);
    EXPECT_EQ(meta_factory->n_created, 1u);
    EXPECT_EQ(meta_factory->last->payload_seen, "v=1,type=external");
}

// The factory is optional: TLSCryptMetadata::verify() accepts by default, so an embedder
// with nothing to check has no reason to configure one. A session without it makes no
// handler, runs no hook, and comes up all the same.
TEST_F(PsidCookieTlsCryptV2Test, SessionWithoutMetadataFactoryMakesNoHandler)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    pcookie_impl->pcfg_.tls_crypt_metadata_factory.reset();
    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    EXPECT_GT(session.recv(pkt), 0u);
    EXPECT_EQ(meta_factory->n_created, 0u);
}

TEST_F(PsidCookieTlsCryptV2Test, TimestampMetadataIsNotUserMetadata)
{
    // stock tls-crypt-v2-genkey's default: a timestamp, type 0x01. The hook still runs, and
    // sees the type byte saying this is not a CSV record.
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc(std::string("\x68\x74\x9f\x00", 4), 0x01),
                                                          wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    ASSERT_GT(session.recv(pkt), 0u);

    ASSERT_TRUE(meta_factory->last);
    EXPECT_EQ(meta_factory->last->n_calls, 1u);
    EXPECT_EQ(meta_factory->last->type_seen, 0x01);
}

TEST_F(PsidCookieTlsCryptV2Test, WkcWithoutMetadataReportsNoMetadata)
{
    auto f = make_fixture();
    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc(""),
                                                          wkc_v1_op_field());

    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    ASSERT_GT(session.recv(pkt), 0u);

    ASSERT_TRUE(meta_factory->last);
    EXPECT_EQ(meta_factory->last->n_calls, 1u);
    EXPECT_EQ(meta_factory->last->type_seen, -1);
}

// verify() belongs to an embedder, and a bad cookie is all it takes to aim a packet at this
// layer, so nothing a stranger sends may reach the hook. Since the cookie layer judges
// nothing at all, a dropped third packet cannot: it never becomes the session that would ask.
TEST_F(PsidCookieTlsCryptV2Test, DroppedThirdPacketRunsNoMetadataHook)
{
    auto f = make_fixture();
    ProtoSessionID bogus;
    bogus.randomize(*pcookie_impl->pcfg_.rng);

    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          bogus,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    EXPECT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::DROP_2ND);
    // no handler was made for it, so nothing saw the record ...
    EXPECT_EQ(meta_factory->n_created, 0u);
    EXPECT_FALSE(meta_factory->last);
}

// A failed verify() rejects the client, and the session is where that is decided: the packet
// is dropped and the rejection counted. PG's hook never does this -- its metadata is
// informational -- but the plumbing honours it.
TEST_F(PsidCookieTlsCryptV2Test, PacketRejectedByMetadataHookIsDroppedAndCounted)
{
    auto f = make_fixture();
    meta_factory->accept = false;

    BufferAllocated pkt = build_third_packet_tls_crypt_v2(f.cli_psid,
                                                          f.cookie_psid,
                                                          make_wkc("v=1,type=external"),
                                                          wkc_v1_op_field());

    // the cookie layer answers it either way; judging is not its business
    ASSERT_EQ(pcookie_impl->intercept(pkt, f.cli_addr), PsidCookie::Intercept::HANDLE_2ND);

    CookieSession session(spf->clone_proto_config(), f.cookie_psid);
    EXPECT_EQ(session.recv(pkt), 0u);
    EXPECT_EQ(session.rec->names, "TLS_CRYPT_META_FAIL");
}
