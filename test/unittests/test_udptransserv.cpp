#include "test_common.hpp"

#include <openvpn/server/udptransserv.hpp>

using namespace openvpn;
using namespace openvpn::UDPTransportServer;

namespace {

using AsioEndpoint = UDPTransportServer::AsioEndpoint;

AsioEndpoint make_v4(const std::string &addr, const unsigned short port)
{
    return AsioEndpoint(openvpn_io::ip::make_address(addr), port);
}

AsioEndpoint make_v6(const std::string &addr, const unsigned short port)
{
    return AsioEndpoint(openvpn_io::ip::make_address(addr), port);
}

// The cookie HMAC (psid_cookie_impl.hpp) depends on this slab being a
// reproducible, collision-resistant encoding of the client's transport
// address. These tests exist because a subtle bug here (wrong byte order,
// missing scope, two endpoints aliasing) would silently weaken or break the
// flood-defense cookie without any test elsewhere noticing, since the cookie
// itself is only exercised end-to-end against a real client.

} // namespace

TEST(ClientAddrInfo, V4SlabHasMappedPrefixAndCorrectSize)
{
    const AsioEndpoint ep = make_v4("203.0.113.7", 4433);
    ClientAddrInfo info(ep);

    size_t slab_size = 0;
    const unsigned char *slab = info.get_abstract_cli_addrport(slab_size);
    ASSERT_EQ(slab_size, 18u); // 16-byte v4-mapped v6 address + 2-byte port

    // Bytes 0-9 are the IPv4-mapped-IPv6 zero prefix.
    for (size_t i = 0; i < 10; ++i)
        ASSERT_EQ(slab[i], 0) << "byte " << i;

    // Bytes 10-11 are the IPv4-mapped marker (0xff 0xff).
    ASSERT_EQ(slab[10], 0xff);
    ASSERT_EQ(slab[11], 0xff);

    // Bytes 12-15 are the IPv4 address, 203.0.113.7.
    ASSERT_EQ(slab[12], 203);
    ASSERT_EQ(slab[13], 0);
    ASSERT_EQ(slab[14], 113);
    ASSERT_EQ(slab[15], 7);

    // Bytes 16-17 are the port, big-endian: 4433 = 0x1151.
    ASSERT_EQ(slab[16], 0x11);
    ASSERT_EQ(slab[17], 0x51);
}

TEST(ClientAddrInfo, V6SlabHoldsFullAddressAndPort)
{
    const AsioEndpoint ep = make_v6("2001:db8::1", 51820);
    ClientAddrInfo info(ep);

    size_t slab_size = 0;
    const unsigned char *slab = info.get_abstract_cli_addrport(slab_size);
    ASSERT_EQ(slab_size, 18u);

    // 2001:0db8:0000:0000:0000:0000:0000:0001
    const unsigned char expected[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    for (size_t i = 0; i < 16; ++i)
        ASSERT_EQ(slab[i], expected[i]) << "byte " << i;

    // Port 51820 = 0xCA6C, big-endian.
    ASSERT_EQ(slab[16], 0xca);
    ASSERT_EQ(slab[17], 0x6c);
}

TEST(ClientAddrInfo, SameEndpointProducesIdenticalSlab)
{
    // The cookie's second-packet check must reproduce the exact same slab
    // from the same client address it saw on the first packet.
    const AsioEndpoint ep = make_v4("198.51.100.9", 1194);
    ClientAddrInfo info_a(ep);
    ClientAddrInfo info_b(ep);

    size_t size_a = 0, size_b = 0;
    const unsigned char *slab_a = info_a.get_abstract_cli_addrport(size_a);
    const unsigned char *slab_b = info_b.get_abstract_cli_addrport(size_b);

    ASSERT_EQ(size_a, size_b);
    ASSERT_EQ(0, std::memcmp(slab_a, slab_b, size_a));
}

TEST(ClientAddrInfo, DifferentPortsProduceDifferentSlabs)
{
    ClientAddrInfo info_a(make_v4("198.51.100.9", 1194));
    ClientAddrInfo info_b(make_v4("198.51.100.9", 1195));

    size_t size_a = 0, size_b = 0;
    const unsigned char *slab_a = info_a.get_abstract_cli_addrport(size_a);
    const unsigned char *slab_b = info_b.get_abstract_cli_addrport(size_b);

    ASSERT_EQ(size_a, size_b);
    ASSERT_NE(0, std::memcmp(slab_a, slab_b, size_a));
}

TEST(ClientAddrInfo, DifferentAddressesProduceDifferentSlabs)
{
    ClientAddrInfo info_a(make_v4("198.51.100.9", 1194));
    ClientAddrInfo info_b(make_v4("198.51.100.10", 1194));

    size_t size_a = 0, size_b = 0;
    const unsigned char *slab_a = info_a.get_abstract_cli_addrport(size_a);
    const unsigned char *slab_b = info_b.get_abstract_cli_addrport(size_b);

    ASSERT_EQ(size_a, size_b);
    ASSERT_NE(0, std::memcmp(slab_a, slab_b, size_a));
}

TEST(ClientAddrInfo, V4AndItsV6MappedFormIntentionallyAlias)
{
    // The v4 branch unconditionally writes the IPv4-mapped marker (0xff 0xff
    // at bytes 10-11), so the only address that can produce the same slab as
    // a v4 client is that same address expressed as a native IPv6 endpoint in
    // mapped form (::ffff:a.b.c.d) -- the same client, seen through a
    // dual-stack socket. That equivalence is intentional, not a collision:
    // there is no way to construct two *different* clients whose slabs match,
    // since a v6 address outside mapped form can never carry that marker.
    ClientAddrInfo v4(make_v4("203.0.113.7", 4433));
    ClientAddrInfo v6(make_v6("::ffff:203.0.113.7", 4433));

    size_t size4 = 0, size6 = 0;
    const unsigned char *slab4 = v4.get_abstract_cli_addrport(size4);
    const unsigned char *slab6 = v6.get_abstract_cli_addrport(size6);

    ASSERT_EQ(size4, size6);
    ASSERT_EQ(0, std::memcmp(slab4, slab6, size4));
}

TEST(ClientAddrInfo, ImplInfoReturnsTheOriginalEndpoint)
{
    const AsioEndpoint ep = make_v4("192.0.2.55", 443);
    ClientAddrInfo info(ep);

    const auto *recovered = static_cast<const AsioEndpoint *>(info.get_impl_info());
    ASSERT_NE(recovered, nullptr);
    ASSERT_EQ(*recovered, ep);
}

namespace {

// Builds a raw DATA_V2 header: opcode 9 in the top 5 bits of byte 0 (key id
// 0 in the low 3 bits), then a 24-bit big-endian peer id filling the rest of
// the 4-byte header. Mirrors exactly what ProtoContext::KeyContext::encrypt()
// writes on the wire (proto.hpp's op32_compose), which is what
// extract_peer_id_hint() must parse back.
BufferAllocated make_data_v2_packet(const std::uint32_t peer_id)
{
    BufferAllocated buf(4, BufAllocFlags::NO_FLAGS);
    buf.inc_size(4);
    const std::uint32_t op32 = htonl((9u << 27) | (peer_id & 0x00FFFFFF));
    std::memcpy(buf.data(), &op32, sizeof(op32));
    return buf;
}

} // namespace

TEST(ExtractPeerIdHint, ParsesAPresentPeerId)
{
    const BufferAllocated buf = make_data_v2_packet(42);
    const auto peer_id = extract_peer_id_hint(buf);

    ASSERT_TRUE(peer_id.has_value());
    ASSERT_EQ(*peer_id, 42);
}

TEST(ExtractPeerIdHint, ReturnsNulloptForTheUndefinedSentinel)
{
    const BufferAllocated buf = make_data_v2_packet(0x00FFFFFF);
    ASSERT_FALSE(extract_peer_id_hint(buf).has_value());
}

TEST(ExtractPeerIdHint, ReturnsNulloptForNonDataV2Opcodes)
{
    // CONTROL_V1 = 4, key id 0 -> byte0 = 4 << 3 = 0x20. Control packets
    // don't carry a small peer id in this header shape at all.
    BufferAllocated buf(4, BufAllocFlags::NO_FLAGS);
    buf.inc_size(4);
    std::memset(buf.data(), 0, 4);
    buf.data()[0] = 4 << 3;

    ASSERT_FALSE(extract_peer_id_hint(buf).has_value());
}

TEST(ExtractPeerIdHint, ReturnsNulloptForATruncatedHeader)
{
    BufferAllocated buf(3, BufAllocFlags::NO_FLAGS);
    buf.inc_size(3);
    buf.data()[0] = static_cast<unsigned char>(9u << 3);

    ASSERT_FALSE(extract_peer_id_hint(buf).has_value());
}

TEST(ExtractPeerIdHint, DistinguishesTwoDifferentPeerIds)
{
    const auto a = extract_peer_id_hint(make_data_v2_packet(1));
    const auto b = extract_peer_id_hint(make_data_v2_packet(2));

    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    ASSERT_NE(*a, *b);
}

// --- new-session shape gate ---------------------------------------------
//
// With neither tls-auth nor tls-crypt configured the psid cookie declines and
// validate_initial_packet() returns true unconditionally (servproto.hpp), so
// this is the only thing standing between an arbitrary datagram and a fully
// allocated session with an SSL context.

namespace {

BufferAllocated make_opcode_packet(const unsigned int opcode, const unsigned int key_id = 0)
{
    BufferAllocated buf(4, BufAllocFlags::NO_FLAGS);
    const std::uint8_t op = static_cast<std::uint8_t>((opcode << 3) | key_id);
    buf.write(&op, 1);
    const std::uint8_t rest[3] = {0, 0, 0};
    buf.write(rest, 3);
    return buf;
}

// Mirrors of ProtoContext's opcode enum (openvpn/ssl/proto.hpp). Duplicated
// rather than referenced because that enum is protected, so it is unreachable
// from a test; hoisting it out of the class would let these go.
constexpr unsigned int HARD_RESET_CLIENT_V2 = 7;
constexpr unsigned int HARD_RESET_CLIENT_V3 = 10;
constexpr unsigned int HARD_RESET_SERVER_V2 = 8;
constexpr unsigned int DATA_V2_OPCODE = 9;
constexpr unsigned int CONTROL_V1 = 4;

} // namespace

TEST(LooksLikeClientReset, AcceptsHardResetClientV2)
{
    const BufferAllocated buf = make_opcode_packet(HARD_RESET_CLIENT_V2);
    ASSERT_TRUE(UDPTransportServer::looks_like_client_reset(buf));
}

TEST(LooksLikeClientReset, AcceptsHardResetClientV3)
{
    const BufferAllocated buf = make_opcode_packet(HARD_RESET_CLIENT_V3);
    ASSERT_TRUE(UDPTransportServer::looks_like_client_reset(buf));
}

TEST(LooksLikeClientReset, RejectsAnEmptyBuffer)
{
    // The concrete regression: a failed peer-float attempt leaves the buffer
    // emptied by the decrypt it just failed, and the no-cookie path used to
    // build a session out of it.
    const BufferAllocated buf;
    ASSERT_FALSE(UDPTransportServer::looks_like_client_reset(buf));
}

TEST(LooksLikeClientReset, RejectsDataAndMidSessionControlOpcodes)
{
    ASSERT_FALSE(UDPTransportServer::looks_like_client_reset(make_opcode_packet(DATA_V2_OPCODE)));
    ASSERT_FALSE(UDPTransportServer::looks_like_client_reset(make_opcode_packet(CONTROL_V1)));
}

TEST(LooksLikeClientReset, RejectsAServerSideOpcode)
{
    ASSERT_FALSE(UDPTransportServer::looks_like_client_reset(make_opcode_packet(HARD_RESET_SERVER_V2)));
}

TEST(LooksLikeClientReset, RejectsAResetOnANonZeroKeyId)
{
    // An opening packet is always key id 0; anything else is mid-session.
    ASSERT_FALSE(UDPTransportServer::looks_like_client_reset(
        make_opcode_packet(HARD_RESET_CLIENT_V2, /*key_id=*/3)));
}

TEST(ClientAddrInfo, SurvivesConstructionFromATemporary)
{
    // endpoint_ is stored by value; when it was a reference, get_impl_info()
    // handed out a pointer into a destroyed temporary.
    ClientAddrInfo info(make_v4("198.51.100.9", 1194));

    const auto *recovered = static_cast<const AsioEndpoint *>(info.get_impl_info());
    ASSERT_NE(recovered, nullptr);
    ASSERT_EQ(recovered->address().to_string(), "198.51.100.9");
    ASSERT_EQ(recovered->port(), 1194);
}
