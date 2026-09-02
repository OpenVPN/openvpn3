#include "test_common.hpp"
#include "test_caps.hpp"


#include <filesystem>
#include <ranges>

#include <openvpn/frame/frame_init.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/server/tunreal.hpp>

using namespace openvpn;

namespace {

// Builds a minimal, otherwise-zeroed IPv4 packet with the given source and
// destination, exactly as far as extract_addrs()/extract_dest_addr() look:
// version/header-length nibble and the address fields. Header contents
// beyond that are irrelevant to the functions under test.
BufferAllocated make_v4_packet(const std::string &dest,
                               const size_t total_size = sizeof(IPv4Header),
                               const std::string &src = "0.0.0.0")
{
    BufferAllocated buf(total_size, BufAllocFlags::NO_FLAGS);
    buf.inc_size(total_size);
    std::memset(buf.data(), 0, total_size);

    if (total_size >= sizeof(IPv4Header))
    {
        auto *hdr = reinterpret_cast<IPv4Header *>(buf.data());
        hdr->version_len = IPv4Header::ver_len(IPCommon::IPv4, sizeof(IPv4Header));
        hdr->saddr = IPv4::Addr::from_string(src).to_uint32_net();
        hdr->daddr = IPv4::Addr::from_string(dest).to_uint32_net();
    }
    else
    {
        buf.data()[0] = static_cast<unsigned char>(IPCommon::IPv4 << 4);
    }
    return buf;
}

BufferAllocated make_v6_packet(const std::string &dest,
                               const size_t total_size = sizeof(IPv6Header),
                               const std::string &src = "::")
{
    BufferAllocated buf(total_size, BufAllocFlags::NO_FLAGS);
    buf.inc_size(total_size);
    std::memset(buf.data(), 0, total_size);

    if (total_size >= sizeof(IPv6Header))
    {
        auto *hdr = reinterpret_cast<IPv6Header *>(buf.data());
        hdr->version_prio = static_cast<unsigned char>(IPCommon::IPv6 << 4);
        const in6_addr s = IPv6::Addr::from_string(src).to_in6_addr();
        std::memcpy(&hdr->saddr, &s, sizeof(s));
        const in6_addr d = IPv6::Addr::from_string(dest).to_in6_addr();
        std::memcpy(&hdr->daddr, &d, sizeof(d));
    }
    else
    {
        buf.data()[0] = static_cast<unsigned char>(IPCommon::IPv6 << 4);
    }
    return buf;
}

} // namespace

TEST(ExtractDestAddr, ParsesIPv4Destination)
{
    const BufferAllocated buf = make_v4_packet("203.0.113.7");
    const auto addr = TunReal::extract_dest_addr(buf);

    ASSERT_TRUE(addr.has_value());
    ASSERT_EQ(*addr, IP::Addr::from_string("203.0.113.7"));
}

TEST(ExtractDestAddr, ParsesIPv6Destination)
{
    const BufferAllocated buf = make_v6_packet("2001:db8::1");
    const auto addr = TunReal::extract_dest_addr(buf);

    ASSERT_TRUE(addr.has_value());
    ASSERT_EQ(*addr, IP::Addr::from_string("2001:db8::1"));
}

TEST(ExtractDestAddr, EmptyBufferReturnsNullopt)
{
    BufferAllocated buf;
    ASSERT_FALSE(TunReal::extract_dest_addr(buf).has_value());
}

TEST(ExtractDestAddr, TruncatedIPv4HeaderReturnsNullopt)
{
    // Declares IPv4 in the version nibble but is too short to hold a full
    // header, let alone the destination field within it.
    const BufferAllocated buf = make_v4_packet("203.0.113.7", 8);
    ASSERT_FALSE(TunReal::extract_dest_addr(buf).has_value());
}

TEST(ExtractDestAddr, TruncatedIPv6HeaderReturnsNullopt)
{
    const BufferAllocated buf = make_v6_packet("2001:db8::1", 8);
    ASSERT_FALSE(TunReal::extract_dest_addr(buf).has_value());
}

TEST(ExtractDestAddr, UnknownIpVersionReturnsNullopt)
{
    BufferAllocated buf(sizeof(IPv4Header), BufAllocFlags::NO_FLAGS);
    buf.inc_size(sizeof(IPv4Header));
    std::memset(buf.data(), 0, buf.size());
    buf.data()[0] = 0x50; // version nibble = 5, neither IPv4 nor IPv6

    ASSERT_FALSE(TunReal::extract_dest_addr(buf).has_value());
}

TEST(ExtractAddrs, ParsesIPv4SourceAndDestination)
{
    const BufferAllocated buf = make_v4_packet("203.0.113.7", sizeof(IPv4Header), "198.51.100.9");
    const auto addrs = TunReal::extract_addrs(buf);

    ASSERT_TRUE(addrs.has_value());
    ASSERT_EQ(addrs->src, IP::Addr::from_string("198.51.100.9"));
    ASSERT_EQ(addrs->dst, IP::Addr::from_string("203.0.113.7"));
}

TEST(ExtractAddrs, ParsesIPv6SourceAndDestination)
{
    const BufferAllocated buf = make_v6_packet("2001:db8::1", sizeof(IPv6Header), "2001:db8::2");
    const auto addrs = TunReal::extract_addrs(buf);

    ASSERT_TRUE(addrs.has_value());
    ASSERT_EQ(addrs->src, IP::Addr::from_string("2001:db8::2"));
    ASSERT_EQ(addrs->dst, IP::Addr::from_string("2001:db8::1"));
}

// --- ingress reverse-path filter ---------------------------------------
//
// Without this, a client reaches any other client by sourcing from an
// address outside the pool, since an unresolvable source carries no policy
// signal of its own.

TEST(SourceIsPermitted, AcceptsThePacketsOwnAssignedAddress)
{
    ASSERT_TRUE(TunReal::source_is_permitted(IP::Addr::from_string("10.8.0.2"),
                                             IP::Addr::from_string("10.8.0.2")));
}

TEST(SourceIsPermitted, RejectsAnotherClientsAddress)
{
    ASSERT_FALSE(TunReal::source_is_permitted(IP::Addr::from_string("10.8.0.3"),
                                              IP::Addr::from_string("10.8.0.2")));
}

TEST(SourceIsPermitted, RejectsTheServersOwnGateway)
{
    ASSERT_FALSE(TunReal::source_is_permitted(IP::Addr::from_string("10.8.0.1"),
                                              IP::Addr::from_string("10.8.0.2")));
}

TEST(SourceIsPermitted, RejectsAnAddressOutsideThePoolEntirely)
{
    // The bypass this closes: a source outside the pool resolves to no
    // session downstream, so on the egress side this packet would be
    // indistinguishable from legitimate non-client traffic.
    const IP::Addr spoofed = IP::Addr::from_string("8.8.8.8");
    const IP::Addr assigned = IP::Addr::from_string("10.8.0.2");

    ASSERT_FALSE(TunReal::source_is_permitted(spoofed, assigned));
}

// --- device lifecycle (root-gated) --------------------------------------
//
// TunLinux::Tun sets TunIO::retain_stream, so TunIO detaches the descriptor
// rather than closing it and the client's TunPersist/ScopedFD is the real
// owner. TunReal::Device has no TunPersist, so it must own the fd itself;
// without that every start/stop cycle leaked a descriptor and left the tunN
// interface up for the life of the process. Needs CAP_NET_ADMIN, so it self-
// skips unprivileged like the sitnl suite.

namespace {


size_t open_fd_count()
{
    return static_cast<size_t>(
        std::ranges::distance(std::filesystem::directory_iterator("/proc/self/fd")));
}

TunReal::Config device_config()
{
    TunReal::Config c;
    c.dev_name = "tuntrtest0";
    c.gateway = IP::Addr::from_string("10.222.0.1");
    c.prefix_len = 24;
    return c;
}

} // namespace

class TunRealDeviceTest : public testing::Test
{
  protected:
    void SetUp() override
    {
        if (!openvpn::test::have_cap_net_admin())
            GTEST_SKIP() << "Need CAP_NET_ADMIN to open a tun device";

        frame = frame_init_simple(2048);
        stats.reset(new SessionStats());

        // One throwaway cycle before the baseline. asio's io_context allocates
        // its reactor descriptors (epoll, event, timer) when the first I/O
        // object is constructed, not at construction of the io_context, so a
        // baseline taken before that counts three fds that are never returned
        // and have nothing to do with the tun device.
        {
            TunReal::Device::Ptr warmup(new TunReal::Device(io_context, device_config(), frame, stats, &routes));
        }
        baseline = open_fd_count();
    }

    openvpn_io::io_context io_context{1};
    PeerRoutes::RouteTable routes;
    Frame::Ptr frame;
    SessionStats::Ptr stats;
    size_t baseline = 0;
};

TEST_F(TunRealDeviceTest, StopClosesTheDescriptorAndRemovesTheInterface)
{
    {
        TunReal::Device::Ptr dev(new TunReal::Device(io_context, device_config(), frame, stats, &routes));
        ASSERT_EQ(dev->iface_name(), "tuntrtest0");
        ASSERT_TRUE(std::filesystem::exists("/sys/class/net/tuntrtest0"));
        dev->stop();
    }

    ASSERT_EQ(open_fd_count(), baseline);
    ASSERT_FALSE(std::filesystem::exists("/sys/class/net/tuntrtest0"));
}

TEST_F(TunRealDeviceTest, RepeatedCyclesDoNotAccumulateDescriptors)
{
    for (int i = 0; i < 8; ++i)
    {
        TunReal::Device::Ptr dev(new TunReal::Device(io_context, device_config(), frame, stats, &routes));
        dev->stop();
    }

    ASSERT_EQ(open_fd_count(), baseline);
}

TEST_F(TunRealDeviceTest, DestructionWithoutStopAlsoClosesTheDescriptor)
{
    {
        TunReal::Device::Ptr dev(new TunReal::Device(io_context, device_config(), frame, stats, &routes));
    }
    ASSERT_EQ(open_fd_count(), baseline);
    ASSERT_FALSE(std::filesystem::exists("/sys/class/net/tuntrtest0"));
}
