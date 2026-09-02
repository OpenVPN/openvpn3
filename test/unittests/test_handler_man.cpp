#include "test_common.hpp"

#include <utility>

#include <openvpn/server_api/handler_man.hpp>

using namespace openvpn;
using namespace openvpn::ServerAPI;

namespace {

class FakeSession : public ManClientInstance::Recv, public TunClientInstance::Recv
{
  public:
    void stop() override
    {
    }
    void tun_recv(BufferAllocated & /* buf */) override
    {
    }
    void auth_failed(const std::string & /* reason */, const std::string & /* client_reason */) override
    {
        auth_failed_calls++;
    }
    void push_reply(std::vector<BufferPtr> &&push_msgs) override
    {
        push_reply_calls++;
        for (const auto &m : push_msgs)
            last_push += buf_to_string(*m);
    }
    void push_halt_restart_msg(const HaltRestart::Type /* type */,
                               const std::string & /* reason */,
                               const std::string & /* client_reason */) override
    {
    }
    void post_cc_msg(BufferPtr && /* msg */) override
    {
    }
    void schedule_disconnect(const unsigned int /* seconds */) override
    {
    }
    void schedule_auth_pending_timeout(const unsigned int seconds) override
    {
        pending_timeout_seconds = seconds;
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

    int auth_failed_calls = 0;
    int push_reply_calls = 0;
    std::string last_push;
    unsigned int pending_timeout_seconds = 0;
};

// Minimal handler satisfying ServerEventHandler: records every callback.
class RecordingHandler
{
  public:
    void on_client_auth(const AuthRequest &req, AuthDecision decision)
    {
        auth_calls++;
        last_common_name = req.common_name;
        pending_decision = std::move(decision);
    }
    void on_client_connected(const ClientInfo &client)
    {
        connected_calls++;
        last_connected_addr = client.vpn_address;
        last_connected_common_name = client.common_name;
        last_connected_transport_info = client.transport_info;
    }
    void on_client_disconnected(const ClientInfo & /* client */, DisconnectReason reason)
    {
        disconnected_calls++;
        last_disconnect_reason = reason;
    }
    void on_stats(const ServerStats & /* stats */)
    {
    }

    int auth_calls = 0;
    int connected_calls = 0;
    int disconnected_calls = 0;
    std::string last_common_name;
    IP::Addr last_connected_addr;
    std::string last_connected_common_name;
    std::string last_connected_transport_info;
    DisconnectReason last_disconnect_reason = DisconnectReason::ServerShutdown;
    std::optional<AuthDecision> pending_decision;
};

static_assert(ServerEventHandler<RecordingHandler>);

HandlerMan::Config::Ptr make_config()
{
    HandlerMan::Config::Ptr c(new HandlerMan::Config());
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

// auth_request() takes an RCPtr(this) internally (AuthDecision's completion
// target), which is only safe for a heap-allocated, RC-managed object -- the
// same requirement the real ManClientInstance::Send::Ptr contract already
// imposes on every factory (SimpleMan, TunSink, TunReal all `new` their
// Instance and return it via a Ptr; never a stack local). Tests must follow
// the same contract instead of the more convenient stack-local pattern
// earlier tests in this suite (SimpleMan, TunSink) got away with -- those
// never took a self-referential RCPtr, so the distinction didn't matter yet.
using TestInstance = HandlerMan::ManSend<RecordingHandler>;

// Owns the pool and route table a Lease needs, so a test that only cares
// about auth/push machinery does not have to build both. The pool starts at
// 10.8.0.2, so the first lease taken always carries that address.
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
        PeerRoutes::Config c;
        c.pool_start = IP::Addr::from_string("10.8.0.2");
        c.pool_size = pool_size;
        return c;
    }

    PeerRoutes::AddressPool pool;
    PeerRoutes::RouteTable table;
};

RCPtr<TestInstance> make_instance(TestRoutes &routes,
                                  FakeSession *session,
                                  RecordingHandler &handler,
                                  const std::uint64_t instance_id = 1)
{
    // No TransportClientInstance::Recv / DcoServ::Channel here: these tests
    // exercise the handler-driven auth/push machinery, not DCO engagement
    // (see test_dcoserv.cpp and the dedicated DCO-aware fixture below for
    // that) -- nullptr/empty Ptr mirrors what Factory::new_man_obj()'s
    // dynamic_cast yields for a session that doesn't implement the
    // transport interface, exactly what FakeSession is here.
    return RCPtr<TestInstance>(new TestInstance(session, nullptr, make_config(), handler, DcoServ::Channel::Ptr(), instance_id, routes.lease(session)));
}

} // namespace

TEST(HandlerManSend, AuthRequestInvokesHandlerWithCertCommonName)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    AuthCert::Ptr cert(new AuthCert("Test-Client", 12345));
    inst->auth_request(AuthCreds::Ptr(), cert, PeerAddr::Ptr());

    ASSERT_EQ(handler.auth_calls, 1);
    ASSERT_EQ(handler.last_common_name, "Test-Client");
    ASSERT_EQ(session.push_reply_calls, 0); // no verdict yet
}

// client_info() (used for on_client_connected/on_client_disconnected) must
// report the real cert CN when one was presented, not the auth-user-pass
// username -- even when both were presented at once, matching what
// AuthRequest::common_name already reports during on_client_auth().
TEST(HandlerManSend, ClientInfoPrefersCertCommonNameOverUsername)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    AuthCert::Ptr cert(new AuthCert("Test-Client", 12345));
    inst->auth_request(make_auth_creds("alice"), cert, PeerAddr::Ptr());
    ASSERT_TRUE(handler.pending_decision.has_value());

    handler.pending_decision->allow();
    ASSERT_EQ(handler.connected_calls, 1);
    ASSERT_EQ(handler.last_connected_common_name, "Test-Client");
}

// A client with no certificate (e.g. --client-cert-optional) falls back to
// the auth-user-pass username instead of reporting an empty common name.
TEST(HandlerManSend, ClientInfoFallsBackToUsernameWithNoCert)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    ASSERT_TRUE(handler.pending_decision.has_value());

    handler.pending_decision->allow();
    ASSERT_EQ(handler.connected_calls, 1);
    ASSERT_EQ(handler.last_connected_common_name, "alice");
}

TEST(HandlerManSend, AllowThenPushRequestPushesExactlyOnce)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    ASSERT_TRUE(handler.pending_decision.has_value());

    handler.pending_decision->allow();
    ASSERT_EQ(handler.connected_calls, 1);
    ASSERT_EQ(session.push_reply_calls, 0); // allowed, but no push requested yet

    inst->push_request(nullptr);
    ASSERT_EQ(session.push_reply_calls, 1);

    // A duplicate push_request (e.g. a retransmit) must not push again.
    inst->push_request(nullptr);
    ASSERT_EQ(session.push_reply_calls, 1);
}

TEST(HandlerManSend, PushRequestThenAllowPushesExactlyOnce)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->push_request(nullptr);
    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    ASSERT_EQ(session.push_reply_calls, 0);

    handler.pending_decision->allow();
    ASSERT_EQ(session.push_reply_calls, 1);
}

// DisconnectReason::AuthFailed is a documented public value; before this it
// was unreachable, because notify_disconnected()'s connected_notified_ gate
// swallowed complete_deny()'s call and a denied client produced no closing
// event at all.
TEST(HandlerManSend, DenyReportsAuthFailedToTheHandler)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    handler.pending_decision->deny(DenyReason::InvalidCredentials);

    ASSERT_EQ(handler.connected_calls, 0);
    ASSERT_EQ(handler.disconnected_calls, 1);
    ASSERT_EQ(handler.last_disconnect_reason, DisconnectReason::AuthFailed);
}

// ...and the subsequent teardown must not report the same session a second
// time with a different reason.
TEST(HandlerManSend, StopAfterDenyDoesNotReportTwice)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    handler.pending_decision->deny(DenyReason::InvalidCredentials);
    inst->disconnect_notify(DisconnectCause::SERVER_SHUTDOWN);
    inst->stop();

    ASSERT_EQ(handler.disconnected_calls, 1);
    ASSERT_EQ(handler.last_disconnect_reason, DisconnectReason::AuthFailed);
}

TEST(HandlerManSend, DenyCallsAuthFailedAndNeverPushes)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->push_request(nullptr);
    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    handler.pending_decision->deny(DenyReason::InvalidCredentials);

    ASSERT_EQ(session.auth_failed_calls, 1);
    ASSERT_EQ(session.push_reply_calls, 0);
    ASSERT_EQ(handler.connected_calls, 0);
}

TEST(HandlerManSend, PendingSchedulesAuthPendingTimeout)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    handler.pending_decision->pending(30);

    ASSERT_EQ(session.pending_timeout_seconds, 30u);
    ASSERT_EQ(session.push_reply_calls, 0);
}

TEST(HandlerManSend, DoubleCompletionIsANoOp)
{
    // AuthDecision's doc comment promises a second completion is a silent
    // no-op, not an error -- exercised here via allow() then deny().
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->push_request(nullptr);
    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    handler.pending_decision->allow();
    ASSERT_EQ(session.push_reply_calls, 1);

    handler.pending_decision->deny(DenyReason::PolicyDenied);
    ASSERT_EQ(session.auth_failed_calls, 0); // verdict already settled, deny() is a no-op
    ASSERT_EQ(handler.connected_calls, 1);
}

TEST(HandlerManSend, StopSuppressesFurtherPush)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    inst->stop();
    handler.pending_decision->allow();
    inst->push_request(nullptr);

    ASSERT_EQ(session.push_reply_calls, 0);
    ASSERT_TRUE(inst->is_stopped());
}

// transport_info reached the embedder empty: peer_addr_ was captured in
// auth_request() but never copied into ClientInfo, so serv.cpp logged a
// dangling "... from ".
TEST(HandlerManSend, ClientInfoCarriesTransportInfo)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    PeerAddr::Ptr peer(new PeerAddr());
    peer->remote.addr = IP::Addr::from_string("198.51.100.7");
    peer->remote.port = 1194;
    peer->local.addr = IP::Addr::from_string("192.0.2.1");
    peer->local.port = 1194;

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), peer);
    handler.pending_decision->allow();

    ASSERT_EQ(handler.connected_calls, 1);
    ASSERT_EQ(handler.last_connected_transport_info, peer->to_string());
    ASSERT_NE(handler.last_connected_transport_info.find("198.51.100.7"), std::string::npos);
}

// Every teardown path reaches the embedder, carrying the cause the protocol
// session recorded. Before this, on_client_disconnected fired only for a
// denied auth, so Timeout and ClientRequested were unreachable.
class HandlerManDisconnect : public ::testing::TestWithParam<std::pair<DisconnectCause, DisconnectReason>>
{
};

TEST_P(HandlerManDisconnect, StopReportsTheRecordedCause)
{
    const auto [cause, expected] = GetParam();

    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    handler.pending_decision->allow();
    ASSERT_EQ(handler.connected_calls, 1);
    ASSERT_EQ(handler.disconnected_calls, 0);

    inst->disconnect_notify(cause);
    inst->stop();

    ASSERT_EQ(handler.disconnected_calls, 1);
    ASSERT_EQ(handler.last_disconnect_reason, expected);
}

INSTANTIATE_TEST_SUITE_P(
    Causes,
    HandlerManDisconnect,
    ::testing::Values(
        std::make_pair(DisconnectCause::KEEPALIVE_TIMEOUT, DisconnectReason::Timeout),
        std::make_pair(DisconnectCause::CLIENT_EXIT, DisconnectReason::ClientRequested),
        std::make_pair(DisconnectCause::SERVER_SHUTDOWN, DisconnectReason::ServerShutdown),
        std::make_pair(DisconnectCause::UNKNOWN, DisconnectReason::SessionError)));

TEST(HandlerManSend, DisconnectNotifiesExactlyOnce)
{
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    handler.pending_decision->allow();

    inst->stop();
    inst->stop();

    ASSERT_EQ(handler.disconnected_calls, 1);
}

TEST(HandlerManSend, NoDisconnectWithoutAConnect)
{
    // A session torn down before it was ever admitted never reached
    // on_client_connected, so it must not produce an unpaired disconnect.
    TestRoutes routes;
    FakeSession session;
    RecordingHandler handler;
    auto inst = make_instance(routes, &session, handler);

    inst->disconnect_notify(DisconnectCause::CLIENT_EXIT);
    inst->stop();

    ASSERT_EQ(handler.connected_calls, 0);
    ASSERT_EQ(handler.disconnected_calls, 0);
}

TEST(HandlerManSend, StopReleasesPoolAddressAfterDeniedAuth)
{
    // The leak this guards: a session denied before push_reply() never gets a
    // tun instance, so releasing from the tun layer would never run for it.
    TestRoutes routes(1);
    RecordingHandler handler;
    FakeSession session;
    auto inst = make_instance(routes, &session, handler);
    ASSERT_EQ(routes.table.size(), 1u);

    inst->auth_request(make_auth_creds("alice"), AuthCert::Ptr(), PeerAddr::Ptr());
    handler.pending_decision->deny(DenyReason::InvalidCredentials);
    inst->stop();

    ASSERT_EQ(routes.table.size(), 0u);

    // The single-address pool is usable again, which it would not be if the
    // denied session had held on to its assignment.
    FakeSession next;
    ASSERT_NO_THROW(routes.lease(&next));
}

TEST(HandlerManSend, StopReleasesPoolAddressForConnectedSession)
{
    TestRoutes routes;
    RecordingHandler handler;
    HandlerMan::ManFactory<RecordingHandler> factory(make_config(), handler, &routes.pool, &routes.table);

    FakeSession session;
    ManClientInstance::Send::Ptr inst = factory.new_man_obj(&session);
    ASSERT_EQ(routes.table.size(), 1u);

    inst->stop();
    ASSERT_EQ(routes.table.size(), 0u);
    ASSERT_EQ(routes.pool.available(), 252u);
}

// Destroying the instance without anyone calling stop() must still give the
// address back: that is the whole point of the lease being a member rather
// than a release obligation on a teardown path.
TEST(HandlerManSend, DestructionAloneReleasesThePoolAddress)
{
    TestRoutes routes;
    RecordingHandler handler;
    HandlerMan::ManFactory<RecordingHandler> factory(make_config(), handler, &routes.pool, &routes.table);

    FakeSession session;
    {
        ManClientInstance::Send::Ptr inst = factory.new_man_obj(&session);
        ASSERT_EQ(routes.table.size(), 1u);
    }

    ASSERT_EQ(routes.table.size(), 0u);
    ASSERT_EQ(routes.pool.available(), 252u);
}

TEST(HandlerManFactory, AssignsAddressAndConstructsInstance)
{
    TestRoutes routes;
    RecordingHandler handler;
    HandlerMan::ManFactory<RecordingHandler> factory(make_config(), handler, &routes.pool, &routes.table);

    FakeSession session;
    ManClientInstance::Send::Ptr inst = factory.new_man_obj(&session);

    ASSERT_TRUE(inst);
    ASSERT_NE(inst->describe_user(false).find("10.8.0.2"), std::string::npos);
}
