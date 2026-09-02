#include "test_common.hpp"

#include <openvpn/server/simpleman.hpp>

using namespace openvpn;

namespace {

// Records everything ServerProto::Session would receive back from the
// management layer, so tests can assert on push-gating and push-reply
// content without any protocol/TLS/socket machinery.
//
// Also implements TunClientInstance::Recv, mirroring how the real Session
// multiply-inherits both interfaces (see peerroutes.hpp's doc comment): the
// Factory tests below need dynamic_cast<TunClientInstance::Recv*> on this
// object to succeed, exactly as it does on a real Session, so PeerRoutes sees
// a distinct identity per fake session rather than every instance aliasing to
// a null cast target.
class FakeManRecv : public ManClientInstance::Recv, public TunClientInstance::Recv
{
  public:
    void stop() override
    {
        stop_calls++;
    }

    void tun_recv(BufferAllocated & /* buf */) override
    {
    }

    void auth_failed(const std::string &reason, const std::string & /* client_reason */) override
    {
        auth_failed_calls++;
        last_auth_failed_reason = reason;
    }

    void push_reply(std::vector<BufferPtr> &&push_msgs) override
    {
        push_reply_calls++;
        for (const auto &msg : push_msgs)
            last_push += buf_to_string(*msg);
    }

    void push_halt_restart_msg(const HaltRestart::Type /* type */,
                               const std::string &reason,
                               const std::string & /* client_reason */) override
    {
        halt_calls++;
        last_halt_reason = reason;
    }

    void post_cc_msg(BufferPtr && /* msg */) override
    {
    }

    void schedule_disconnect(const unsigned int /* seconds */) override
    {
    }

    void schedule_auth_pending_timeout(const unsigned int /* seconds */) override
    {
    }

    void relay(const IP::Addr & /* target */, const int /* port */) override
    {
    }

    PeerStats stats_poll() override
    {
        return PeerStats();
    }

    bool should_preserve_session_id() override
    {
        return false;
    }

    TunClientInstance::NativeHandle tun_native_handle() override
    {
        return TunClientInstance::NativeHandle();
    }

    int stop_calls = 0;
    int auth_failed_calls = 0;
    int push_reply_calls = 0;
    int halt_calls = 0;
    std::string last_auth_failed_reason;
    std::string last_push;
    std::string last_halt_reason;
};

SimpleMan::Config::Ptr make_config()
{
    SimpleMan::Config::Ptr c(new SimpleMan::Config());
    c->gateway = IP::Addr::from_string("10.8.0.1");
    c->prefix_len = 24;
    c->keepalive_ping = 10;
    c->keepalive_timeout = 60;
    return c;
}

AuthCreds::Ptr make_auth_creds(const std::string &username)
{
    return AuthCreds::Ptr(new AuthCreds(username, SafeString(""), OptionList()));
}

ProtoContext::ProtoConfig::Ptr make_proto_config_with_cipher(const std::string &cipher_name)
{
    ProtoContext::ProtoConfig::Ptr pc(new ProtoContext::ProtoConfig());
    pc->dc.set_cipher(CryptoAlgs::lookup(cipher_name));
    return pc;
}

// Owns the pool and route table a Lease needs. Pool starts at 10.8.0.2, so
// the first lease taken always carries that address.
//
// Declare one *before* anything that can outlive the Instance -- a
// RecordingHandler retains the AuthDecision, which holds an RCPtr to the
// Instance and so to its Lease. A TestRoutes declared after the handler is
// destroyed first, and the Lease then releases into freed storage.
struct TestRoutes
{
    explicit TestRoutes(const unsigned int pool_size = 252)
        : pool(config(pool_size))
    {
    }

    PeerRoutes::Lease lease(TunClientInstance::Recv *session)
    {
        return PeerRoutes::Lease(pool, table, session);
    }

    static PeerRoutes::Config config(const unsigned int pool_size)
    {
        return PeerRoutes::Config{.pool_start = IP::Addr::from_string("10.8.0.2"),
                                  .pool_size = pool_size};
    }

    PeerRoutes::AddressPool pool;
    PeerRoutes::RouteTable table;
};

} // namespace

TEST(SimpleManFactory, AssignsAddressesSequentially)
{
    // Address assignment itself is PeerRoutes' job (test_peerroutes.cpp);
    // this asserts only that the factory delegates to it and that the
    // assigned address reaches the pushed/describable Instance.
    TestRoutes routes;
    SimpleMan::ManFactory factory(make_config(), &routes.pool, &routes.table);
    FakeManRecv r1, r2, r3;

    ManClientInstance::Send::Ptr i1 = factory.new_man_obj(&r1);
    ManClientInstance::Send::Ptr i2 = factory.new_man_obj(&r2);
    ManClientInstance::Send::Ptr i3 = factory.new_man_obj(&r3);

    // Address assignment is only observable via describe_user()'s rendering.
    ASSERT_NE(i1->describe_user(false).find("10.8.0.2"), std::string::npos);
    ASSERT_NE(i2->describe_user(false).find("10.8.0.3"), std::string::npos);
    ASSERT_NE(i3->describe_user(false).find("10.8.0.4"), std::string::npos);
}

TEST(SimpleManFactory, PropagatesPeerRoutesExhaustion)
{
    TestRoutes routes(1);
    SimpleMan::ManFactory factory(make_config(), &routes.pool, &routes.table);

    FakeManRecv r1, r2;
    // The first instance has to be held: its Lease releases the address as
    // soon as it dies, so a discarded temporary would free the single-address
    // pool again and the second call would succeed.
    ManClientInstance::Send::Ptr i1;
    ASSERT_NO_THROW(i1 = factory.new_man_obj(&r1));
    ASSERT_THROW(factory.new_man_obj(&r2), PeerRoutes::peer_routes_error);
}

TEST(SimpleManSend, PushFiresExactlyOnceAuthThenPushRequest)
{
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::ManSend inst(&recv, make_config(), 1, inst_routes.lease(&recv));

    inst.auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    ASSERT_EQ(recv.push_reply_calls, 0); // no push yet: not requested

    inst.push_request(nullptr);
    ASSERT_EQ(recv.push_reply_calls, 1);
}

TEST(SimpleManSend, PushFiresExactlyOncePushRequestThenAuth)
{
    // The class doc calls out that both orderings must push exactly once.
    // This is the ordering test_proto's IV_PROTO request-push path exercises;
    // an older client instead sends PUSH_REQUEST after authenticating, which
    // is the order covered above.
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::ManSend inst(&recv, make_config(), 1, inst_routes.lease(&recv));

    inst.push_request(nullptr);
    ASSERT_EQ(recv.push_reply_calls, 0); // no push yet: not authenticated

    inst.auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    ASSERT_EQ(recv.push_reply_calls, 1);
}

TEST(SimpleManSend, DuplicatePushRequestDoesNotPushAgain)
{
    // A client's PUSH_REQUEST retransmit (or an IV_PROTO push follow-up)
    // arriving after the reply was already sent must not re-push: a second
    // push reply re-inits the data channel mid-session.
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::ManSend inst(&recv, make_config(), 1, inst_routes.lease(&recv));

    inst.auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    inst.push_request(nullptr);
    ASSERT_EQ(recv.push_reply_calls, 1);

    inst.push_request(nullptr);
    ASSERT_EQ(recv.push_reply_calls, 1);
}

TEST(SimpleManSend, StopSuppressesAnyLaterPush)
{
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::ManSend inst(&recv, make_config(), 1, inst_routes.lease(&recv));

    inst.auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    inst.stop();
    inst.push_request(nullptr);

    ASSERT_EQ(recv.push_reply_calls, 0);
    ASSERT_TRUE(inst.is_stopped());
}

TEST(SimpleManSend, AuthFallsBackToCertCommonNameWhenNoUsername)
{
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::ManSend inst(&recv, make_config(), 1, inst_routes.lease(&recv));

    AuthCert::Ptr cert(new AuthCert("Test-Client", 12345));
    inst.auth_request(AuthCreds::Ptr(), cert, PeerAddr::Ptr());
    inst.push_request(nullptr);

    // The username is not part of the wire push reply; it is recorded for
    // logging/description only, which is what this asserts.
    ASSERT_NE(inst.describe_user(false).find("Test-Client"), std::string::npos);
}

TEST(SimpleManSend, PushReplyContainsExpectedDirectives)
{
    FakeManRecv recv;
    SimpleMan::Config::Ptr config = make_config();
    config->extra_push.push_back("route 10.0.0.0 255.0.0.0");
    PeerRoutes::Config routes_config;
    routes_config.pool_start = IP::Addr::from_string("10.8.0.5");
    PeerRoutes::AddressPool pool(routes_config);
    PeerRoutes::RouteTable table;
    SimpleMan::ManSend inst(&recv, config, 1, PeerRoutes::Lease(pool, table, &recv));

    inst.auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    inst.push_request(make_proto_config_with_cipher("AES-256-GCM"));

    const std::string &push = recv.last_push;
    ASSERT_NE(push.find("PUSH_REPLY"), std::string::npos);
    ASSERT_NE(push.find("route-gateway 10.8.0.1"), std::string::npos);
    ASSERT_NE(push.find("ifconfig 10.8.0.5 255.255.255.0"), std::string::npos);
    ASSERT_NE(push.find("ping 10"), std::string::npos);
    ASSERT_NE(push.find("ping-restart 60"), std::string::npos);
    ASSERT_NE(push.find("cipher AES-256-GCM"), std::string::npos);
    ASSERT_NE(push.find("route 10.0.0.0 255.0.0.0"), std::string::npos);
}

TEST(SimpleManSend, PushReplyOmitsCipherWhenNoneNegotiated)
{
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::ManSend inst(&recv, make_config(), 1, inst_routes.lease(&recv));

    inst.auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    inst.push_request(nullptr); // no ProtoConfig supplied

    ASSERT_EQ(recv.last_push.find("cipher"), std::string::npos);
}

TEST(SimpleManSend, KeepaliveOverrideAppliesConfiguredValues)
{
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::Config::Ptr config = make_config();
    config->keepalive_ping = 5;
    config->keepalive_timeout = 20;
    SimpleMan::ManSend inst(&recv, config, 1, inst_routes.lease(&recv));

    unsigned int ping = 999, timeout = 999;
    inst.keepalive_override(ping, timeout);

    ASSERT_EQ(ping, 5u);
    ASSERT_EQ(timeout, 20u);
}

TEST(SimpleManSend, DisconnectUserForwardsHaltMessageToSession)
{
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::ManSend inst(&recv, make_config(), 1, inst_routes.lease(&recv));

    inst.disconnect_user(HaltRestart::AUTH_FAILED, static_cast<AuthStatus::Type>(0), "server reason", "client reason");

    ASSERT_EQ(recv.halt_calls, 1);
    ASSERT_EQ(recv.last_halt_reason, "server reason");
}

TEST(SimpleManSend, DisconnectUserIsANoOpAfterStop)
{
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::ManSend inst(&recv, make_config(), 1, inst_routes.lease(&recv));

    inst.stop();
    inst.disconnect_user(HaltRestart::AUTH_FAILED, static_cast<AuthStatus::Type>(0), "reason", "reason");

    ASSERT_EQ(recv.halt_calls, 0);
}

TEST(SimpleManSend, InstanceNameAndIdAreStable)
{
    TestRoutes inst_routes;
    FakeManRecv recv;
    SimpleMan::ManSend inst(&recv, make_config(), 42, inst_routes.lease(&recv));

    ASSERT_EQ(inst.instance_id(), 42u);
    ASSERT_EQ(inst.instance_name(), "CLI_42");
}
