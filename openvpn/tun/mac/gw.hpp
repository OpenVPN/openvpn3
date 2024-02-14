//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2022 OpenVPN Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Get IPv4 gateway info on Mac OS X.

#ifndef OPENVPN_TUN_MAC_GWV4_H
#define OPENVPN_TUN_MAC_GWV4_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet6/in6_var.h>

#include <cstring>
#include <string>
#include <sstream>
#include <algorithm> // for std::max
#include <cstdint>   // for std::uint32_t
#include <memory>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/addrpair.hpp>
#include <openvpn/addr/macaddr.hpp>
#include <ifaddrs.h>

namespace openvpn {
class MacGatewayInfo
{
    struct rtmsg
    {
        struct rt_msghdr m_rtm;
        char m_space[512];
    };

#define OPENVPN_ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a)-1) | (sizeof(std::uint32_t) - 1))) : sizeof(std::uint32_t))

#define OPENVPN_NEXTADDR(w, u)          \
    if (rtm_addrs & (w))                \
    {                                   \
        l = OPENVPN_ROUNDUP(u.sin_len); \
        std::memmove(cp, &(u), l);      \
        cp += l;                        \
    }


#define OPENVPN_NEXTADDR6(w, u)          \
    if (rtm_addrs & (w))                 \
    {                                    \
        l = OPENVPN_ROUNDUP(u.sin6_len); \
        std::memmove(cp, &(u), l);       \
        cp += l;                         \
    }

#define OPENVPN_ADVANCE(x, n) \
    (x += OPENVPN_ROUNDUP((n)->sa_len))

  public:
    OPENVPN_EXCEPTION(route_gateway_error);

    enum
    {
        ADDR_DEFINED = (1 << 0),    /* set if gateway.addr defined */
        NETMASK_DEFINED = (1 << 1), /* set if gateway.netmask defined */
        HWADDR_DEFINED = (1 << 2),  /* set if hwaddr is defined */
        IFACE_DEFINED = (1 << 3),   /* set if iface is defined */
    };

    MacGatewayInfo(IP::Addr dest)
    {
        struct rtmsg m_rtmsg;
        ScopedFD sockfd;
        int seq, l, pid, rtm_addrs;
        sockaddr_in so_dst{}, so_mask{};
        sockaddr_in6 so_dst6{};
        char *cp = m_rtmsg.m_space;
        struct sockaddr *gate = nullptr, *ifp = nullptr, *sa;
        struct rt_msghdr *rtm_aux;

        /* setup data to send to routing socket */
        pid = ::getpid();
        seq = 0;
        rtm_addrs = RTA_DST | RTA_NETMASK | RTA_IFP;

        std::memset(&m_rtmsg, 0, sizeof(m_rtmsg));
        std::memset(&m_rtmsg.m_rtm, 0, sizeof(struct rt_msghdr));

        m_rtmsg.m_rtm.rtm_type = RTM_GET;
        m_rtmsg.m_rtm.rtm_flags = RTF_UP | RTF_GATEWAY;
        m_rtmsg.m_rtm.rtm_version = RTM_VERSION;
        m_rtmsg.m_rtm.rtm_seq = ++seq;
        m_rtmsg.m_rtm.rtm_addrs = rtm_addrs;

        const bool ipv6 = dest.is_ipv6();

        if (!ipv6)
        {
            so_dst = dest.to_ipv4().to_sockaddr();
            // 32 netmask to lookup the route to the destination
            so_mask.sin_family = AF_INET;
            so_mask.sin_addr.s_addr = 0xffffffff;
            so_mask.sin_len = sizeof(struct sockaddr_in);

            OPENVPN_NEXTADDR(RTA_DST, so_dst);
            OPENVPN_NEXTADDR(RTA_NETMASK, so_mask);
        }
        else
        {
            so_dst6 = dest.to_ipv6().to_sockaddr();
            OPENVPN_NEXTADDR6(RTA_DST, so_dst6);
        }

        m_rtmsg.m_rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

        /* transact with routing socket */
        sockfd.reset(socket(PF_ROUTE, SOCK_RAW, 0));
        if (!sockfd.defined())
            throw route_gateway_error("GDG: socket #1 failed");

        auto ret = ::write(sockfd(), (char *)&m_rtmsg, l);
        if (ret < 0)
            throw route_gateway_error("GDG: problem writing to routing socket: " + std::to_string(ret)
                                      + " errno: " + std::to_string(errno) + " msg: " + ::strerror(errno));

        do
        {
            l = ::read(sockfd(), (char *)&m_rtmsg, sizeof(m_rtmsg));
        } while (l > 0 && (m_rtmsg.m_rtm.rtm_seq != seq || m_rtmsg.m_rtm.rtm_pid != pid));
        sockfd.close();

        /* extract return data from routing socket */
        rtm_aux = &m_rtmsg.m_rtm;
        cp = ((char *)(rtm_aux + 1));
        if (rtm_aux->rtm_addrs)
        {
            for (unsigned int i = 1; i; i <<= 1u)
            {
                if (i & rtm_aux->rtm_addrs)
                {
                    sa = (struct sockaddr *)cp;
                    if (i == RTA_GATEWAY)
                        gate = sa;
                    else if (i == RTA_IFP)
                        ifp = sa;
                    OPENVPN_ADVANCE(cp, sa);
                }
            }
        }
        else
            return;

        /* get gateway addr and interface name */
        if (gate != nullptr)
        {
            /* get default gateway addr */
            gateway_.addr = IP::Addr::from_sockaddr(gate);
            if (!gateway_.addr.unspecified())
                flags_ |= ADDR_DEFINED;

            if (ifp)
            {
                /* get interface name */
                const struct sockaddr_dl *adl = (struct sockaddr_dl *)ifp;
                const size_t len = adl->sdl_nlen;
                if (len && len < sizeof(iface_))
                {
                    std::memcpy(iface_, adl->sdl_data, len);
                    iface_[len] = '\0';
                    flags_ |= IFACE_DEFINED;
                }
            }
        }

        /* get netmask of interface that owns default gateway. Querying the IPv6 netmask does not
         * seem to work on my system (Arne), so it is disabled for now until we can figure out why it
         * doesn't work */
        if (flags_ & IFACE_DEFINED && gateway_.addr.version() == IP::Addr::V4)
        {
            ifreq ifr{};
            sa_family_t sa_family;

            sa_family = AF_INET;
            ifr.ifr_addr.sa_family = sa_family;
            string::strncpynt(ifr.ifr_name, iface_, IFNAMSIZ);

            sockfd.reset(socket(sa_family, SOCK_DGRAM, 0));
            if (!sockfd.defined())
                throw route_gateway_error("GDG: socket #2 failed");

            if (::ioctl(sockfd(), SIOCGIFNETMASK, (char *)&ifr) < 0)
                throw route_gateway_error("GDG: ioctl SIOCGIFNETMASK failed");

            gateway_.netmask = IP::Addr::from_sockaddr(&ifr.ifr_addr));
            flags_ |= NETMASK_DEFINED;

            sockfd.close();
        }

        /* try to read MAC addr associated with interface that owns default gateway */
        if (flags_ & IFACE_DEFINED)
        {
            struct ifaddrs *ifaddrp, *ifa;

            if (getifaddrs(&ifaddrp) != 0)
            {
                throw route_gateway_error("GDG: getifaddrs failed errno: " + std::to_string(errno) + " msg: " + ::strerror(errno));
            }

            /* put the pointer into a unique_ptr to have RAII (allow throwing etc) */
            std::unique_ptr<::ifaddrs, decltype(&::freeifaddrs)> ifap{ifaddrp, &::freeifaddrs};

            for (ifa = ifap.get(); ifa != nullptr; ifa = ifa->ifa_next)
            {
                if (ifa->ifa_addr == nullptr)
                    continue;

                if (flags_ & IFACE_DEFINED
                    && ifa->ifa_addr->sa_family == AF_LINK
                    && !strncmp(ifa->ifa_name, iface_, IFNAMSIZ))
                {
                    const struct sockaddr_dl *sockaddr_dl = reinterpret_cast<struct sockaddr_dl *>(ifa->ifa_addr);

                    hwaddr_.reset(reinterpret_cast<unsigned char *>(LLADDR(sockaddr_dl)));
                    flags_ |= HWADDR_DEFINED;
                }
            }
        }
    }
#undef OPENVPN_ROUNDUP
#undef OPENVPN_NEXTADDR
#undef OPENVPN_NEXTADDR6
#undef OPENVPN_ADVANCE

    std::string info() const
    {
        std::ostringstream os;
        os << "GATEWAY";
        if (flags_ & ADDR_DEFINED)
        {
            os << " ADDR=" << gateway_.addr;
            if (flags_ & NETMASK_DEFINED)
            {
                os << '/' << gateway_.netmask;
            }
        }
        if (flags_ & IFACE_DEFINED)
            os << " IFACE=" << iface_;
        if (flags_ & HWADDR_DEFINED)
            os << " HWADDR=" << hwaddr_;
        return os.str();
    }

    unsigned int flags() const
    {
        return flags_;
    }
    const IP::Addr &gateway_addr() const
    {
        return gateway_.addr;
    }
    std::string gateway_addr_str() const
    {
        return gateway_addr().to_string();
    }
    const IP::Addr &gateway_netmask() const
    {
        return gateway_.netmask;
    }
    std::string gateway_netmask_str() const
    {
        return gateway_netmask().to_string();
    }
    std::string iface() const
    {
        return iface_;
    }
    const MACAddr &hwaddr() const
    {
        return hwaddr_;
    }

    bool iface_addr_defined() const
    {
        return (flags_ & (ADDR_DEFINED | IFACE_DEFINED)) == (ADDR_DEFINED | IFACE_DEFINED);
    }

    bool hwaddr_defined() const
    {
        return flags_ & HWADDR_DEFINED;
    }

  private:
    unsigned int flags_ = 0;
    IP::AddrMaskPair gateway_;
    char iface_[16];
    MACAddr hwaddr_;
};

} // namespace openvpn

#endif
