//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2024- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#include "test_common.hpp"
#include "test_generators.hpp"

#include <set>
#include <vector>

#include <openvpn/addr/addrlist.hpp>

RC_GTEST_PROP(AddrList, AddMarksAddressAsExisting, ())
{
    openvpn::IP::AddrList address_list;
    const auto address = *rc::genIPAddr();
    address_list.add(address);
    RC_ASSERT(address_list.exists(address));
}

RC_GTEST_PROP(AddrList, AddIsIdempotent, ())
{
    openvpn::IP::AddrList list;
    const auto addr = *rc::genIPAddr();
    list.add(addr);
    list.add(addr);
    RC_ASSERT(list.size() == 1U);
    RC_ASSERT(list[0] == addr);
}

RC_GTEST_PROP(AddrList, AddDistinctAddressesKeepsUniqueCount, ())
{
    const auto addrs = *rc::gen::container<std::vector<openvpn::IP::Addr>>(rc::genIPAddr());
    const std::set unique_addrs(addrs.begin(), addrs.end());
    openvpn::IP::AddrList list;
    for (const auto &addr : addrs)
    {
        list.add(addr);
    }
    RC_ASSERT(list.size() == unique_addrs.size());
}

RC_GTEST_PROP(AddrList, ExistsMatchesMembership, ())
{
    const auto addrs = *rc::gen::container<std::vector<openvpn::IP::Addr>>(rc::genIPAddr());
    const std::set unique_addrs(addrs.begin(), addrs.end());
    openvpn::IP::AddrList list;
    for (const auto &addr : addrs)
    {
        list.add(addr);
    }
    const auto probe = *rc::gen::oneOf(rc::gen::elementOf(unique_addrs), rc::genIPAddr());
    const bool expected = unique_addrs.contains(probe);
    RC_ASSERT(list.exists(probe) == expected);
}
