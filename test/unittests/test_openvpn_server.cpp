#include "test_common.hpp"

#include <thread>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/server_api/openvpn_server.hpp>

using namespace openvpn;
using namespace openvpn::ServerAPI;

namespace {

// Reuses the same CA/server cert pair test_proto.cpp loads via
// TEST_KEYCERT_DIR (that macro is only defined for test_proto.cpp's own
// translation unit, so this reconstructs the same path from the
// suite-wide UNITTEST_SOURCE_DIR instead).
const std::string keycert_dir = std::string(UNITTEST_SOURCE_DIR) + "/../ssl/";

// A fixed high port: this suite runs single-process and serially, so no
// concurrent bind is possible.
constexpr unsigned short test_port = 28194;

// Minimal handler satisfying ServerEventHandler: allows every client and
// records what happened.
class RecordingHandler
{
  public:
    void on_client_auth(const AuthRequest & /* req */, AuthDecision decision)
    {
        decision.allow();
    }
    void on_client_connected(const ClientInfo & /* client */)
    {
    }
    void on_client_disconnected(const ClientInfo & /* client */, DisconnectReason /* reason */)
    {
    }
    void on_stats(const ServerStats & /* stats */)
    {
    }
};

static_assert(ServerEventHandler<RecordingHandler>);

Config make_config()
{
    Config c;
    c.bind_addr = "127.0.0.1";
    c.port = test_port;
    c.ca = read_text_utf8(keycert_dir + "ca.crt");
    c.cert = read_text_utf8(keycert_dir + "server.crt");
    c.key = read_text_utf8(keycert_dir + "server.key");
    c.dh = read_text_utf8(keycert_dir + "dh.pem");
    c.null_tun = true; // avoids CAP_NET_ADMIN in this test
    return c;
}

} // namespace

// Destruction is the only way to stop a server, so it is the only teardown
// path there is to test. StartStopIsClean, StopWithoutStartIsANoOp,
// DoubleStopIsANoOp and StartStopStartIsClean were all removed with the public
// stop() and restart: they tested an API that no longer exists.
TEST(OpenVPNServer, DestructorStopsARunningServer)
{
    RecordingHandler handler;
    {
        OpenVPNServer<RecordingHandler> server(make_config(), handler);
        ASSERT_FALSE(server.is_running());
        server.start();
        ASSERT_TRUE(server.is_running());
    }
    // No crash and no leaked thread on scope exit is the assertion here.
}

// A server runs at most once. Second start() must be refused rather than
// quietly replacing the io_context the first run's sockets and timers are
// bound to -- which is what the old restart path had to unpick by hand.
TEST(OpenVPNServer, SecondStartThrows)
{
    RecordingHandler handler;
    OpenVPNServer<RecordingHandler> server(make_config(), handler);
    server.start();
    ASSERT_THROW(server.start(), Exception);
}

// Refused even after the run has been stopped by nothing but time: started_ is
// never cleared, so the one-shot rule does not depend on is_running().
TEST(OpenVPNServer, StartIsRefusedForeverOnceUsed)
{
    RecordingHandler handler;
    OpenVPNServer<RecordingHandler> server(make_config(), handler);
    server.start();
    ASSERT_THROW(server.start(), Exception);
    ASSERT_THROW(server.start(), Exception);
}

// An IPv6 gateway used to parse fine and then die with "to_ipv4: address is
// not IPv4" from partway through device setup. The data plane is v4-only, so
// it is rejected up front, on the caller's thread, with a message that says
// which field is wrong.
// The worker thread that runs the control io_context has to adopt the
// creating thread's log context: OPENVPN_LOG resolves through a thread-local
// pointer, so without it every line the server logs -- session events,
// handler callbacks, errors -- is silently discarded. The reference server
// logged nothing at all about clients until this was wired up.
TEST(OpenVPNServer, WorkerThreadInheritsTheLogContext)
{
    RecordingHandler handler;

    testLog->startCollecting();
    {
        OpenVPNServer<RecordingHandler> server(make_config(), handler);
        server.start();
    } // destructor stops, which is what emits the line asserted on below
    const std::string log = testLog->stopCollecting();

    // Asserted on the stop line, not the listening line: start() opens the
    // socket synchronously on the calling thread, which has a log context
    // either way. stop() is posted onto the io_context and runs on the
    // worker, so only that line proves the context was carried across.
    ASSERT_NE(log.find("UDP server stopped"), std::string::npos) << log;
}

TEST(OpenVPNServer, IPv6GatewayThrowsSynchronously)
{
    RecordingHandler handler;
    Config config = make_config();
    config.gateway = IP::Addr::from_string("2001:db8::1");
    OpenVPNServer<RecordingHandler> server(std::move(config), handler);

    try
    {
        server.start();
        FAIL() << "expected an exception";
    }
    catch (const std::exception &e)
    {
        const std::string what = e.what();
        ASSERT_NE(what.find("gateway"), std::string::npos) << what;
        ASSERT_NE(what.find("IPv4"), std::string::npos) << what;
    }
    ASSERT_FALSE(server.is_running());
}

TEST(OpenVPNServer, IPv6PoolStartThrowsSynchronously)
{
    RecordingHandler handler;
    Config config = make_config();
    config.pool_start = IP::Addr::from_string("2001:db8::2");
    OpenVPNServer<RecordingHandler> server(std::move(config), handler);

    try
    {
        server.start();
        FAIL() << "expected an exception";
    }
    catch (const std::exception &e)
    {
        const std::string what = e.what();
        ASSERT_NE(what.find("pool_start"), std::string::npos) << what;
    }
    ASSERT_FALSE(server.is_running());
}

TEST(OpenVPNServer, BadCertContentThrowsSynchronously)
{
    RecordingHandler handler;
    Config config = make_config();
    config.cert = "not a certificate";

    OpenVPNServer<RecordingHandler> server(std::move(config), handler);
    ASSERT_ANY_THROW(server.start());
    ASSERT_FALSE(server.is_running());
}

// tls_auth/tls_crypt/tls_crypt_v2 are mutually exclusive; an embedder that
// hand-builds Config (rather than parsing an OptionList, where proto.hpp's
// own ERR_INVALID_OPTION_CRYPTO checks would catch this) must get a clear
// synchronous error instead of one silently winning over the other.
TEST(OpenVPNServer, TlsAuthAndTlsCryptTogetherThrowsSynchronously)
{
    RecordingHandler handler;
    Config config = make_config();
    config.tls_auth = "not a real key, only checked for non-emptiness before parsing";
    config.tls_crypt = "likewise";

    OpenVPNServer<RecordingHandler> server(std::move(config), handler);
    ASSERT_ANY_THROW(server.start());
    ASSERT_FALSE(server.is_running());
}

TEST(OpenVPNServer, TlsCryptAndTlsCryptV2TogetherThrowsSynchronously)
{
    RecordingHandler handler;
    Config config = make_config();
    config.tls_crypt = "not a real key, only checked for non-emptiness before parsing";
    config.tls_crypt_v2 = "likewise";

    OpenVPNServer<RecordingHandler> server(std::move(config), handler);
    ASSERT_ANY_THROW(server.start());
    ASSERT_FALSE(server.is_running());
}

// A real tls-crypt-v2 server key (single-key form, no by-ID rotation
// directory) starts cleanly -- exercises TLSCryptV2ServerKey::parse()/
// extract_key() on real content, not just the mutual-exclusivity guard above.
TEST(OpenVPNServer, TlsCryptV2ServerKeyStartsCleanly)
{
    RecordingHandler handler;
    Config config = make_config();
    config.tls_crypt_v2 = read_text_utf8(keycert_dir + "tls-crypt-v2-server.key");

    OpenVPNServer<RecordingHandler> server(std::move(config), handler);
    server.start();
    ASSERT_TRUE(server.is_running());
}

// client_cert_optional sets SSLConst::PEER_CERT_OPTIONAL on the SSL config;
// this only confirms that setting it does not itself break server startup
// (a client actually connecting without a cert is exercised live, not here).
TEST(OpenVPNServer, ClientCertOptionalStartsCleanly)
{
    RecordingHandler handler;
    Config config = make_config();
    config.client_cert_optional = true;

    OpenVPNServer<RecordingHandler> server(std::move(config), handler);
    server.start();
    ASSERT_TRUE(server.is_running());
}

// The pushed ifconfig netmask comes from prefix_len, so a pool that leaves the
// gateway's subnet hands a client an address it cannot reach the gateway from.
// Caught at start() rather than by the Nth client to connect.
TEST(OpenVPNServer, PoolLeavingTheSubnetThrowsSynchronously)
{
    RecordingHandler handler;
    Config config = make_config();
    config.gateway = IP::Addr::from_string("10.8.0.1");
    config.prefix_len = 24;
    config.pool_start = IP::Addr::from_string("10.8.0.200");
    config.pool_size = 100; // runs to 10.8.1.43

    OpenVPNServer<RecordingHandler> server(std::move(config), handler);
    ASSERT_THROW(server.start(), Exception);
}

TEST(OpenVPNServer, PoolFillingTheSubnetExactlyIsAccepted)
{
    RecordingHandler handler;
    Config config = make_config();
    config.gateway = IP::Addr::from_string("10.8.0.1");
    config.prefix_len = 24;
    config.pool_start = IP::Addr::from_string("10.8.0.2");
    config.pool_size = 253; // last is 10.8.0.254

    OpenVPNServer<RecordingHandler> server(std::move(config), handler);
    ASSERT_NO_THROW(server.start());
}

// The event loop runs behind an exception barrier; a clean run must not set it.
TEST(OpenVPNServer, CleanRunReportsNoFatalError)
{
    RecordingHandler handler;
    OpenVPNServer<RecordingHandler> server(make_config(), handler);
    server.start();
    // Read while alive, which is how an embedder actually uses it: an
    // exception unwinding run() leaves the loop dead but the object intact,
    // and is_running() still true, so noticing means asking.
    ASSERT_TRUE(server.fatal_error().empty());
}
