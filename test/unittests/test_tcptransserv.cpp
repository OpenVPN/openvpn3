#include "test_common.hpp" // IWYU pragma: keep
#include "test_transserv_fakes.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <openvpn/io/io.hpp>

#include <asio/buffer.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/tcp.hpp>

#include <openvpn/frame/frame_init.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/server/tcptransserv.hpp>
#include <openvpn/ssl/proto.hpp>

using openvpn::frame_init_simple;
using openvpn::ProtoContext;
using openvpn::SessionStats;
using openvpn::TCPTransportServer::AsioEndpoint;
using openvpn::TCPTransportServer::Config;
using openvpn::TCPTransportServer::Server;
namespace test = openvpn::test;

namespace {

/**
 * @brief A started TCP server on 127.0.0.1 backed by @c test::FakeFactory,
 *  with a one-packet send queue so a second unsent packet overflows.
 */
class TCPServerTest : public testing::Test
{
  protected:
    /** @brief Bind the server to an ephemeral loopback port. */
    void SetUp() override
    {
        Config::Ptr config(new Config());
        config->bind_addr = "127.0.0.1";
        config->port = 0;
        config->frame = frame_init_simple(test::test_frame_payload);
        config->stats.reset(new SessionStats());
        config->send_queue_max_packets = 1;
        factory.reset(new test::FakeFactory(io_context, new ProtoContext::ProtoConfig()));
        server.reset(new Server(io_context, std::move(config), factory));
        server->start();
    }

    /**
     * @brief Open @p count client connections, each sending a framed hard
     *  reset, and wait until every one has a started session.
     * @param count Number of clients.
     * @return True if all @p count sessions started.
     */
    bool connect_clients(const std::size_t count)
    {
        const AsioEndpoint server_endpoint(openvpn_io::ip::make_address("127.0.0.1"),
                                           test::port_of(server->local_endpoint_info()));
        // 16-bit big-endian length prefix, then the packet.
        constexpr auto framed = std::to_array<std::uint8_t>({0, 4, test::client_reset_opcode, 0, 0, 0});
        for (std::size_t index = 0; index < count; ++index)
        {
            auto &sock = clients.emplace_back(client_io_context);
            sock.connect(server_endpoint);
            if (sock.send(openvpn_io::buffer(framed)) != framed.size())
            {
                return false;
            }
        }
        return test::pump_until(io_context, [&]
                                { return factory->sessions.size() == count && server->n_clients() == count; });
    }

    /**
     * @brief Check that stop() notified, stopped and disconnected every
     *  session exactly once, and emptied the table.
     */
    void expect_all_halted() const
    {
        std::vector<int> halt_msgs;
        std::vector<int> stop_calls;
        std::vector<bool> sendable;
        for (const auto &session : factory->sessions)
        {
            halt_msgs.push_back(session->halt_msgs);
            stop_calls.push_back(session->stop_calls);
            sendable.push_back(session->send->defined());
        }
        const std::size_t count = factory->sessions.size();
        EXPECT_EQ(halt_msgs, std::vector<int>(count, 1));
        EXPECT_EQ(stop_calls, std::vector<int>(count, 1));
        EXPECT_EQ(sendable, std::vector<bool>(count, false));
        EXPECT_EQ(server->n_clients(), 0U);
    }

    /** @brief Stop the server and drain its cancelled handlers. */
    void TearDown() override
    {
        server->stop();
        io_context.restart();
        io_context.run();
    }

    openvpn_io::io_context io_context{1};
    openvpn_io::io_context client_io_context{1};
    std::vector<openvpn_io::ip::tcp::socket> clients;
    test::FakeFactory::Ptr factory;
    Server::Ptr server;
};

} // namespace

TEST_F(TCPServerTest, StopNotifiesEveryClientWhenOneOverflowsMidLoop)
{
    // The middle session's second packet overflows its queue, which erases
    // its table entry from inside stop()'s notification loop.
    factory->halt_msg_packets = {1, 2, 1};
    ASSERT_TRUE(connect_clients(3));

    server->stop();

    expect_all_halted();
}

TEST_F(TCPServerTest, StopSurvivesEveryClientOverflowing)
{
    factory->halt_msg_packets = {2, 2, 2};
    ASSERT_TRUE(connect_clients(3));

    server->stop();

    expect_all_halted();
}

TEST_F(TCPServerTest, StopNotifiesEveryClientOnce)
{
    ASSERT_TRUE(connect_clients(3));

    server->stop();

    expect_all_halted();
}
