#include "test_common.hpp"

#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/server/tunsink.hpp>

using namespace openvpn;

namespace {

class FakeTunRecv : public TunClientInstance::Recv
{
  public:
    void stop() override
    {
        stop_calls++;
    }

    void tun_recv(BufferAllocated & /* buf */) override
    {
    }

    void push_halt_restart_msg(const HaltRestart::Type /* type */,
                               const std::string & /* reason */,
                               const std::string & /* client_reason */) override
    {
    }

    int stop_calls = 0;
};

} // namespace

TEST(TunSink, SendConstAlwaysSucceedsAndLeavesBufferUntouched)
{
    FakeTunRecv parent;
    TunSink::TunSend inst(&parent);

    BufferAllocated buf(16, BufAllocFlags::NO_FLAGS);
    buf_append_string(buf, "payload");
    const size_t size_before = buf.size();

    ASSERT_TRUE(inst.tun_send_const(buf));
    ASSERT_EQ(buf.size(), size_before);
}

TEST(TunSink, SendAlwaysSucceedsAndEmptiesBuffer)
{
    FakeTunRecv parent;
    TunSink::TunSend inst(&parent);

    BufferAllocated buf(16, BufAllocFlags::NO_FLAGS);
    buf_append_string(buf, "payload");
    ASSERT_GT(buf.size(), 0u);

    ASSERT_TRUE(inst.tun_send(buf));
    ASSERT_EQ(buf.size(), 0u);
}

TEST(TunSink, NativeHandleIsUndefined)
{
    FakeTunRecv parent;
    TunSink::TunSend inst(&parent);

    const TunClientInstance::NativeHandle h = inst.tun_native_handle();
    ASSERT_FALSE(h.fd_defined());
    ASSERT_FALSE(h.defined());
}

TEST(TunSink, TunInfoIsStable)
{
    FakeTunRecv parent;
    TunSink::TunSend inst(&parent);
    ASSERT_EQ(inst.tun_info(), "NULL_TUN");
}

TEST(TunSink, StopIsIdempotentAndSendsStillSucceedAfter)
{
    // Documents current behaviour: TunSink never backpressures, even after
    // stop(). A real data-plane backend is expected to start failing sends
    // once stopped; this backend intentionally does not, since it has no
    // failure mode to report.
    FakeTunRecv parent;
    TunSink::TunSend inst(&parent);

    inst.stop();
    inst.stop();

    BufferAllocated buf(8, BufAllocFlags::NO_FLAGS);
    buf_append_string(buf, "x");
    ASSERT_TRUE(inst.tun_send_const(buf));
}

TEST(TunSink, RelayIsANoOpAndDoesNotThrow)
{
    FakeTunRecv parent;
    TunSink::TunSend inst(&parent);
    ASSERT_NO_THROW(inst.relay(IP::Addr::from_string("10.0.0.1"), 1234));
}

TEST(TunSink, FactoryProducesDistinctInstancesPerClient)
{
    FakeTunRecv parent1;
    FakeTunRecv parent2;
    TunSink::TunFactory factory;

    TunClientInstance::Send::Ptr a = factory.new_tun_obj(&parent1);
    TunClientInstance::Send::Ptr b = factory.new_tun_obj(&parent2);

    ASSERT_TRUE(a);
    ASSERT_TRUE(b);
    ASSERT_NE(a.get(), b.get());
}
