#include "test_common.hpp"

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
    ServerProto::Factory::Ptr spf;

  protected:
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
