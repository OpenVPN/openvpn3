//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#include "test_common.hpp"

#include <openvpn/tun/win/tunutil.hpp>

using namespace openvpn;
using namespace openvpn::TunWin::Util;

namespace unittests {

// public address, so that the route to it is not local
static const std::string dest = "8.8.8.8";

static DWORD default_interface()
{
    DWORD addr;
    inet_pton(AF_INET, dest.c_str(), &addr);
    DWORD index = DWORD(-1);
    ::GetBestInterface(addr, &index);
    return index;
}

TEST(BestGateway, EmptySetIsNoExclusion)
{
    const BestGateway single{AF_INET, dest, DWORD(-1)};
    const BestGateway set{AF_INET, dest, std::set<DWORD>{}};

    EXPECT_EQ(single.defined(), set.defined());
    EXPECT_EQ(single.interface_index(), set.interface_index());
    EXPECT_EQ(single.gateway_address(), set.gateway_address());
}

TEST(BestGateway, SingleIndexMatchesSet)
{
    const DWORD itf = default_interface();
    if (itf == DWORD(-1))
        GTEST_SKIP() << "no route to " << dest;

    const BestGateway single{AF_INET, dest, itf};
    const BestGateway set{AF_INET, dest, std::set<DWORD>{itf}};

    EXPECT_EQ(single.defined(), set.defined());
    EXPECT_EQ(single.interface_index(), set.interface_index());
    EXPECT_EQ(single.gateway_address(), set.gateway_address());
}

TEST(BestGateway, ExcludedInterfacesAreSkipped)
{
    const DWORD itf = default_interface();
    if (itf == DWORD(-1))
        GTEST_SKIP() << "no route to " << dest;

    // an interface that doesn't exist must not change the result
    const BestGateway plain{AF_INET, dest, std::set<DWORD>{}};
    const BestGateway unknown{AF_INET, dest, std::set<DWORD>{0x7ffffff0}};
    EXPECT_EQ(plain.interface_index(), unknown.interface_index());
    EXPECT_EQ(plain.gateway_address(), unknown.gateway_address());

    // excluding the interface of the best route must pick another one, or none
    const BestGateway excluded{AF_INET, dest, std::set<DWORD>{itf, 0x7ffffff0}};
    if (excluded.defined())
    {
        EXPECT_NE(excluded.interface_index(), itf);
    }
}

} // namespace unittests
