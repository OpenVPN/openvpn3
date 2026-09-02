#include "test_common.hpp"

#include <openvpn/server/dcoserv.hpp>

using namespace openvpn;
using namespace openvpn::DcoServ;

namespace {

// Minimal TransportClientInstance::Recv stub: only what find_peer_session()
// needs is a distinct address per instance, so no method bodies matter.
class FakeSession : public TransportClientInstance::Recv
{
  public:
    bool defined() const override
    {
        return true;
    }
    void stop() override
    {
        stop_calls++;
    }
    void start(const TransportClientInstance::Send::Ptr &,
               const PeerAddr::Ptr &,
               const int,
               const ProtoSessionID) override
    {
    }
    bool transport_recv(BufferAllocated &) override
    {
        return true;
    }
    bool is_keepalive_enabled() const override
    {
        return true;
    }
    void disable_keepalive(unsigned int &, unsigned int &) override
    {
    }
    void override_dc_factory(const CryptoDCFactory::Ptr &) override
    {
    }
    TunClientInstance::Recv *override_tun(TunClientInstance::Send *) override
    {
        return nullptr;
    }
    void stats_notify(const PeerStats &, const bool) override
    {
    }
    void float_notify(const PeerAddr::Ptr &) override
    {
    }
    void ipma_notify(const struct ovpn_tun_head_ipma &) override
    {
    }
    void data_limit_notify(const int, const DataLimit::Mode, const DataLimit::State) override
    {
    }
    void push_halt_restart_msg(const HaltRestart::Type, const std::string &, const std::string &) override
    {
    }

    int stop_calls = 0;
};

} // namespace

TEST(DcoServFindPeerSession, UnknownIdReturnsNull)
{
    std::map<int, TransportClientInstance::Recv *> peers;
    FakeSession session;
    peers[1] = &session;

    ASSERT_EQ(find_peer_session(peers, 2), nullptr);
}

TEST(DcoServFindPeerSession, KnownIdReturnsSession)
{
    std::map<int, TransportClientInstance::Recv *> peers;
    FakeSession session_a, session_b;
    peers[1] = &session_a;
    peers[2] = &session_b;

    ASSERT_EQ(find_peer_session(peers, 1), &session_a);
    ASSERT_EQ(find_peer_session(peers, 2), &session_b);
}

TEST(DcoServFindPeerSession, EmptyMapReturnsNull)
{
    std::map<int, TransportClientInstance::Recv *> peers;
    ASSERT_EQ(find_peer_session(peers, 0), nullptr);
}
