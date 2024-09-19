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

#ifndef OPENVPN_TUN_MAC_MACGW_H
#define OPENVPN_TUN_MAC_MACGW_H

#include <string>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/apple/scdynstore.hpp>
#include <openvpn/apple/cf/cfhelper.hpp>

namespace openvpn {
struct MacGWInfo
{
    struct Variant
    {
        friend struct MacGWInfo;

      public:
        bool defined() const
        {
            return !iface.empty() && router.defined();
        }

        std::string to_string() const
        {
            return iface + '/' + router.to_string();
        }

        std::string iface;
        IP::Addr router;

      private:
        Variant()
        {
        }

        Variant(const IP::Addr::Version v, const CF::DynamicStore &dstore)
        {
            const std::string key = std::string("State:/Network/Global/IP") + IP::Addr::version_string_static(v);
            const CF::Dict d(CF::DynamicStoreCopyDict(dstore, key));
            iface = CF::dict_get_str(d, "PrimaryInterface");
            const std::string addr = CF::dict_get_str(d, "Router");
            if (!addr.empty())
                router = IP::Addr::from_string(addr, "MacGWInfo::Variant", v);
            else
                router.reset();
        }
    };

    MacGWInfo()
    {
        const CF::DynamicStore ds(SCDynamicStoreCreate(kCFAllocatorDefault,
                                                       CFSTR("MacGWInfo"),
                                                       nullptr,
                                                       nullptr));
        v4 = Variant(IP::Addr::V4, ds);
        v6 = Variant(IP::Addr::V6, ds);
    }

    std::string to_string() const
    {
        return "IPv4=" + v4.to_string() + " IPv6=" + v6.to_string();
    }

    Variant v4;
    Variant v6;
};
} // namespace openvpn

#endif
