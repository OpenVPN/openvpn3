#include "test_common.hpp"
#include "test_caps.hpp"
#include "test_generators.hpp"


#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include <openvpn/server/netpolicy.hpp>
#include <openvpn/tun/linux/client/sitnl.hpp>

using namespace openvpn;

namespace {


bool nft_cli_available()
{
    return std::system("command -v nft >/dev/null 2>&1") == 0;
}

bool nft_table_exists(const std::string &table_name)
{
    const std::string cmd = "nft list table ip " + table_name + " >/dev/null 2>&1";
    return std::system(cmd.c_str()) == 0;
}

int read_dev_forwarding(const std::string &dev_name)
{
    std::ifstream f("/proc/sys/net/ipv4/conf/" + dev_name + "/forwarding");
    int v = -1;
    f >> v;
    return v;
}

NetPolicy::Attachment make_attachment(const std::string &dev_name, const std::string &gateway)
{
    NetPolicy::Attachment att;
    att.dev_name = dev_name;
    att.gateway = IP::Addr::from_string(gateway);
    att.prefix_len = 24;
    att.client_to_client = false;
    return att;
}

} // namespace

TEST(ValidateForTableName, PassesEveryCharacterNftAccepts)
{
    ASSERT_EQ(NetPolicy::detail::validate_for_table_name("tun0"), "tun0");
    ASSERT_EQ(NetPolicy::detail::validate_for_table_name("ovpn_s0"), "ovpn_s0");
    // nft takes these verbatim, so folding them to '_' only destroyed information.
    ASSERT_EQ(NetPolicy::detail::validate_for_table_name("tun-0.x"), "tun-0.x");
}

TEST(ValidateForTableName, RejectsCharactersNftCannotRepresent)
{
    ASSERT_THROW(NetPolicy::detail::validate_for_table_name("tun:0"), NetPolicy::netpolicy_error);
    ASSERT_THROW(NetPolicy::detail::validate_for_table_name("tun 0"), NetPolicy::netpolicy_error);
}

TEST(ValidateForTableName, RejectsAnEmptyName)
{
    // Previously every unusable name collapsed to "dev", which was itself a
    // collision between any two such devices.
    ASSERT_THROW(NetPolicy::detail::validate_for_table_name(""), NetPolicy::netpolicy_error);
}

/// PROPERTY: distinct interface names yield distinct table names.
/// @details Holds by construction now that the mapping is the identity over the accepted
///  set. It previously failed: every non-alphanumeric character folded to '_', so two
///  devices differing only in separator shared one nft table, and attaching either
///  destroyed the other's client-to-client DROP rule.
RC_GTEST_PROP(ValidateForTableName, DistinctDeviceNamesGetDistinctTableNames, ())
{
    static constexpr std::string_view IFNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-";
    static constexpr std::string_view SEPARATOR_CHARS = "-._";

    const auto base = *rc::gen::scale(0.5, rc::string_from_allowed_chars(IFNAME_CHARS)).as("base name");

    const auto separator = *rc::from_allowed_chars(SEPARATOR_CHARS).as("separator");
    const auto other = *rc::gen::distinctFrom(rc::from_allowed_chars(SEPARATOR_CHARS), separator).as("other separator");
    const auto at = *rc::gen::inRange<std::size_t>(0, base.size() + 1).as("insertion index");

    std::string first = base;
    first.insert(at, 1, separator);
    std::string second = base;
    second.insert(at, 1, other);

    RC_ASSERT(NetPolicy::detail::validate_for_table_name(first)
              != NetPolicy::detail::validate_for_table_name(second));
}

/// PROPERTY: an accepted interface name reaches the table name unchanged.
RC_GTEST_PROP(ValidateForTableName, PreservesLengthForEveryNonEmptyName, ())
{
    static constexpr std::string_view IFNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-";

    const auto name = *rc::gen::nonEmpty(rc::gen::scale(0.5, rc::string_from_allowed_chars(IFNAME_CHARS))).as("interface name");

    RC_ASSERT(NetPolicy::detail::validate_for_table_name(name).size() == name.size());
}

// --- live installation (root-gated) -------------------------------------
//
// Runs against the real host's netfilter/proc state, on throwaway dummy
// devices this fixture creates and deletes. Do not add unshare(CLONE_NEWNET)
// here for isolation: it switches the calling thread's namespace for the
// rest of the process, which in this shared gtest binary breaks every test
// that runs afterward, not just this one.

class NetPolicyLiveTest : public testing::Test
{
  protected:
    void SetUp() override
    {
        if (!openvpn::test::have_cap_net_admin())
            GTEST_SKIP() << "Need CAP_NET_ADMIN for netlink/nftables access";
    }

    void TearDown() override
    {
        for (const auto &name : dummies_)
            TunNetlink::SITNL::net_iface_del(name);
    }

    /** @brief Create a dummy netdev, removed automatically at teardown. */
    void make_dummy(const std::string &name)
    {
        ASSERT_EQ(TunNetlink::SITNL::net_iface_new(name, "dummy"), 0)
            << "could not create dummy device " << name;
        dummies_.push_back(name);
    }

  private:
    std::vector<std::string> dummies_;
};

TEST_F(NetPolicyLiveTest, AttachSucceedsAndDetachRemovesIt)
{
    make_dummy("o3nptest0");
    NetPolicy::Policy policy;
    const auto att = make_attachment("o3nptest0", "10.222.0.1");

    ASSERT_NO_THROW(policy.attach(att));
    ASSERT_TRUE(policy.has_attachment("o3nptest0"));
    ASSERT_EQ(policy.attachment_count(), 1u);

    if (nft_cli_available())
    {
        ASSERT_TRUE(nft_table_exists("o3_c2c_o3nptest0"));
    }

    policy.detach("o3nptest0");
    ASSERT_FALSE(policy.has_attachment("o3nptest0"));

    if (nft_cli_available())
    {
        ASSERT_FALSE(nft_table_exists("o3_c2c_o3nptest0"));
    }
}

TEST_F(NetPolicyLiveTest, ClientToClientTrueInstallsNoRule)
{
    make_dummy("o3nptest1");
    NetPolicy::Policy policy;
    auto att = make_attachment("o3nptest1", "10.223.0.1");
    att.client_to_client = true;

    ASSERT_NO_THROW(policy.attach(att));
    ASSERT_TRUE(policy.has_attachment("o3nptest1"));

    if (nft_cli_available())
    {
        ASSERT_FALSE(nft_table_exists("o3_c2c_o3nptest1"));
    }
}

TEST_F(NetPolicyLiveTest, ReattachingTheSameDeviceReplacesItsRule)
{
    make_dummy("o3nptest2");
    NetPolicy::Policy policy;
    ASSERT_NO_THROW(policy.attach(make_attachment("o3nptest2", "10.224.0.1")));
    ASSERT_NO_THROW(policy.attach(make_attachment("o3nptest2", "10.224.0.1")));
    ASSERT_EQ(policy.attachment_count(), 1u);
}

TEST_F(NetPolicyLiveTest, ShutdownDetachesEveryDevice)
{
    make_dummy("o3nptest3");
    make_dummy("o3nptest4");
    NetPolicy::Policy policy;
    ASSERT_NO_THROW(policy.attach(make_attachment("o3nptest3", "10.225.0.1")));
    ASSERT_NO_THROW(policy.attach(make_attachment("o3nptest4", "10.226.0.1")));
    ASSERT_EQ(policy.attachment_count(), 2u);

    policy.shutdown();
    ASSERT_EQ(policy.attachment_count(), 0u);
}

TEST_F(NetPolicyLiveTest, AttachOnMissingDeviceThrows)
{
    NetPolicy::Policy policy;
    ASSERT_THROW(policy.attach(make_attachment("o3npnone0", "10.227.0.1")),
                 NetPolicy::netpolicy_error);
    ASSERT_FALSE(policy.has_attachment("o3npnone0"));
}

TEST_F(NetPolicyLiveTest, AttachEnablesAndDetachRestoresDeviceForwarding)
{
    make_dummy("o3nptest5");
    if (read_dev_forwarding("o3nptest5") != 0)
        GTEST_SKIP() << "host creates devices with forwarding already on; the guard's "
                        "enable/restore is not observable here";

    NetPolicy::Policy policy;
    ASSERT_NO_THROW(policy.attach(make_attachment("o3nptest5", "10.228.0.1")));
    ASSERT_EQ(read_dev_forwarding("o3nptest5"), 1);

    policy.detach("o3nptest5");
    ASSERT_EQ(read_dev_forwarding("o3nptest5"), 0);
}
