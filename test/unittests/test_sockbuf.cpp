#include <fstream>
#include <string>

#include <sys/socket.h>
#include <unistd.h>

#include "test_common.hpp"
#include "test_generators.hpp"
#include "test_caps.hpp"

#include <openvpn/common/sockopt.hpp>
#include <openvpn/transport/sockbuf.hpp>

using namespace openvpn;

namespace {

/**
 * @brief Owns a UDP socket for the duration of a test case.
 * @details The buffer helpers take a raw descriptor, so the tests need a real
 *  socket but nothing else about it: no bind, no connect. Buffer sizing is
 *  valid on an unbound socket.
 */
class ScopedUdpSocket
{
  public:
    ScopedUdpSocket()
        : fd_(::socket(AF_INET, SOCK_DGRAM, 0))
    {
    }

    ~ScopedUdpSocket()
    {
        if (fd_ >= 0)
            ::close(fd_);
    }

    ScopedUdpSocket(const ScopedUdpSocket &) = delete;
    ScopedUdpSocket &operator=(const ScopedUdpSocket &) = delete;

    [[nodiscard]] int fd() const
    {
        return fd_;
    }

  private:
    int fd_;
};

/**
 * @brief Read an integer sysctl.
 * @param path Path under /proc/sys.
 * @return The value, or 0 if it could not be read.
 */
int read_int_sysctl(const char *path)
{
    std::ifstream in(path);
    int value = 0;
    if (in >> value)
        return value;
    return 0;
}

/**
 * @brief Whether this process holds CAP_NET_ADMIN, i.e. whether the privileged
 *  SO_*BUFFORCE path is expected to succeed.
 * @details Same probe as @c test_sitnl.cpp's, which is the established
 *  convention in this suite for gating privileged cases.
 * @return True if CAP_NET_ADMIN is in the effective set.
 */

/** The host's receive-buffer ceiling, which the unprivileged path is clamped to. */
int rmem_max()
{
    return read_int_sysctl("/proc/sys/net/core/rmem_max");
}

} // namespace

// ---------------------------------------------------------------------------
// SockOpt: the raw POSIX primitives
// ---------------------------------------------------------------------------

TEST(SockOptBuf, ZeroRequestIsNoOpButStillReportsInheritedDefault)
{
    const ScopedUdpSocket sock;
    ASSERT_GE(sock.fd(), 0);

    const SockOpt::BufSizeResult res = SockOpt::set_rcvbuf(sock.fd(), 0);

    ASSERT_EQ(res.requested, 0);
    ASSERT_FALSE(res.ok) << "no request was made, so nothing succeeded";
    ASSERT_FALSE(res.forced);
    // The point of reading back on a no-op: a caller logging buffer provenance
    // needs the default it inherited, not a zero.
    ASSERT_GT(res.actual, 0);
}

TEST(SockOptBuf, NegativeRequestIsNoOp)
{
    const ScopedUdpSocket sock;
    ASSERT_GE(sock.fd(), 0);

    const SockOpt::BufSizeResult res = SockOpt::set_sndbuf(sock.fd(), -1);

    ASSERT_FALSE(res.ok);
    ASSERT_EQ(res.requested, -1) << "a negative request is reported verbatim, not clamped";
    ASSERT_FALSE(res.forced);
    ASSERT_GT(res.actual, 0);
}

TEST(SockOptBuf, InvalidDescriptorIsSafe)
{
    const SockOpt::BufSizeResult rcv = SockOpt::set_rcvbuf(-1, 1 << 20);
    const SockOpt::BufSizeResult snd = SockOpt::set_sndbuf(-1, 1 << 20);

    ASSERT_FALSE(rcv.ok);
    ASSERT_EQ(rcv.actual, 0);
    ASSERT_EQ(rcv.requested, 1 << 20) << "the request is reported back even when it could not be made";
    ASSERT_FALSE(rcv.forced);
    ASSERT_FALSE(snd.ok);
    ASSERT_EQ(snd.actual, 0);
    ASSERT_EQ(snd.requested, 1 << 20);
    ASSERT_FALSE(snd.forced);
}

TEST(SockOptBuf, SmallRequestWithinCeilingIsHonoured)
{
    const ScopedUdpSocket sock;
    ASSERT_GE(sock.fd(), 0);

    const int ceiling = rmem_max();
    ASSERT_GT(ceiling, 0) << "could not read net.core.rmem_max";
    // Comfortably under the ceiling, so neither path needs to clamp.
    const int want = ceiling / 4;

    const SockOpt::BufSizeResult res = SockOpt::set_rcvbuf(sock.fd(), want);

    ASSERT_TRUE(res.ok);
    // The kernel doubles the value for its own bookkeeping, so the readback is
    // >= what was asked for. Anything less would mean a silent clamp.
    ASSERT_GE(res.actual, want);
}

TEST(SockOptBuf, PlainSetIsClampedByHostMaximum)
{
    if (openvpn::test::have_cap_net_admin())
        GTEST_SKIP() << "CAP_NET_ADMIN present, so the request is forced rather than clamped";

    const ScopedUdpSocket sock;
    ASSERT_GE(sock.fd(), 0);

    const int ceiling = rmem_max();
    ASSERT_GT(ceiling, 0) << "could not read net.core.rmem_max";
    const int want = ceiling * 4;

    const SockOpt::BufSizeResult res = SockOpt::set_rcvbuf(sock.fd(), want);

    // This is the defect the helper exists to expose: the syscall reports
    // success while granting a fraction of the request. A caller checking only
    // `ok` is fooled; `actual` is the truth.
    ASSERT_TRUE(res.ok);
    ASSERT_FALSE(res.forced);
    ASSERT_LT(res.actual, want) << "expected a silent clamp below the request";
}

/**
 * @brief Privileged cases, skipped as a group without CAP_NET_ADMIN.
 * @details Follows @c test_sitnl.cpp's convention so an unprivileged run
 *  reports a clean skip rather than a failure.
 */
class SockOptBufPrivileged : public testing::Test
{
  protected:
    void SetUp() override
    {
        if (!openvpn::test::have_cap_net_admin())
            GTEST_SKIP() << "Need CAP_NET_ADMIN to exercise SO_RCVBUFFORCE";
    }
};

TEST_F(SockOptBufPrivileged, ForceSetExceedsHostMaximum)
{
    const ScopedUdpSocket sock;
    ASSERT_GE(sock.fd(), 0);

    const int ceiling = rmem_max();
    ASSERT_GT(ceiling, 0) << "could not read net.core.rmem_max";
    const int want = ceiling * 4;

    const SockOpt::BufSizeResult res = SockOpt::set_rcvbuf(sock.fd(), want);

    // The whole reason the helper prefers the forcing variant: at WAN latency a
    // single flow needs a bandwidth-delay product of buffering, which is far
    // above a stock host's ceiling.
    ASSERT_TRUE(res.ok);
    ASSERT_TRUE(res.forced);
    ASSERT_GE(res.actual, want) << "force-set should bypass the ceiling entirely";
}

TEST_F(SockOptBufPrivileged, ForceSetAppliesToSendBufferToo)
{
    const ScopedUdpSocket sock;
    ASSERT_GE(sock.fd(), 0);

    const int want = read_int_sysctl("/proc/sys/net/core/wmem_max") * 4;
    ASSERT_GT(want, 0) << "could not read net.core.wmem_max";

    const SockOpt::BufSizeResult res = SockOpt::set_sndbuf(sock.fd(), want);

    ASSERT_TRUE(res.ok);
    ASSERT_TRUE(res.forced);
    ASSERT_GE(res.actual, want);
}

// ---------------------------------------------------------------------------
// SockBuf::Result: pure provenance reporting
// ---------------------------------------------------------------------------

TEST(SockBufResult, ClampedIsOnlyTrueWhenLessWasGrantedThanAsked)
{
    SockBuf::Result res;

    res = SockBuf::Result{};
    ASSERT_FALSE(res.clamped()) << "nothing requested cannot be clamped";

    res = SockBuf::Result{8388608, 425984, false, true};
    ASSERT_TRUE(res.clamped());

    res = SockBuf::Result{8388608, 16777216, true, true};
    ASSERT_FALSE(res.clamped()) << "kernel doubling is not a clamp";
}

TEST(SockBufResult, ToStringNamesTheDefaultCase)
{
    const SockBuf::Result res{0, 425984, false, false};
    ASSERT_EQ(res.to_string(), "kernel default 425984");
}

TEST(SockBufResult, ToStringDistinguishesForcedFromClamped)
{
    const SockBuf::Result forced{8388608, 16777216, true, true};
    ASSERT_EQ(forced.to_string(), "8388608 requested, 16777216 granted (forced)");

    const SockBuf::Result clamped{8388608, 425984, false, true};
    ASSERT_EQ(clamped.to_string(),
              "8388608 requested, 425984 granted (clamped by host maximum)");

    const SockBuf::Result unforced{100000, 200000, false, true};
    ASSERT_EQ(unforced.to_string(), "100000 requested, 200000 granted (unforced)");
}

TEST(SockBufResult, ToStringReportsAFailedRequest)
{
    const SockBuf::Result res{8388608, 425984, false, false};
    ASSERT_EQ(res.to_string(), "8388608 requested, request failed, 425984 in effect");
}

// ---------------------------------------------------------------------------
// SockBuf: the asio-facing wrapper both transports use
// ---------------------------------------------------------------------------

TEST(SockBufAsio, SizesAnAsioSocketAndReportsTheResult)
{
    openvpn_io::io_context io_context(1);
    openvpn_io::ip::udp::socket sock(io_context);
    sock.open(openvpn_io::ip::udp::v4());

    const int want = rmem_max() / 4;
    ASSERT_GT(want, 0);

    const SockBuf::Result res = SockBuf::set_rcvbuf(sock, want);

    ASSERT_TRUE(res.ok);
    ASSERT_EQ(res.requested, want);
    ASSERT_GE(res.actual, want);
    ASSERT_FALSE(res.to_string().empty());
}

TEST(SockBufAsio, ZeroLeavesTheDefaultAndStillReportsIt)
{
    openvpn_io::io_context io_context(1);
    openvpn_io::ip::udp::socket sock(io_context);
    sock.open(openvpn_io::ip::udp::v4());

    const SockBuf::Result res = SockBuf::set_sndbuf(sock, 0);

    ASSERT_FALSE(res.ok);
    ASSERT_EQ(res.requested, 0);
    ASSERT_FALSE(res.forced);
    ASSERT_GT(res.actual, 0);
    ASSERT_EQ(res.to_string(), "kernel default " + std::to_string(res.actual));
}

/// PROPERTY: an unforced request above the host ceiling is reported as clamped.
/// @details Previously failed: SockBuf::Result::clamped() tests
///  actual < requested against a readback the kernel has already doubled, so it reports a
///  refused request as honoured for every request between the ceiling and twice the ceiling.
RC_GTEST_PROP(SockBufResult, ClampIsReportedWhenTheKernelDoubledTheReadback, ())
{
    // Stock rmem_max/wmem_max values; the readback the kernel reports for each is 2x.
    const int ceiling = *rc::gen::element(131072, 212992, 1048576, 4194304).as("host ceiling");
    const int requested = *rc::gen::inRange(ceiling + 1, 2 * ceiling + 1).as("bytes requested");

    const SockBuf::Result res{.requested = requested, .actual = 2 * ceiling, .forced = false, .ok = true};

    RC_ASSERT(res.clamped());
}
