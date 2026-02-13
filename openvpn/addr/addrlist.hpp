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

#ifndef OPENVPN_ADDR_ADDRLIST_H
#define OPENVPN_ADDR_ADDRLIST_H

#include <algorithm>

#include <openvpn/common/rc.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn::IP {

// A list of unique IP addresses
class AddrList : public std::vector<Addr>, public RC<thread_unsafe_refcount>
{
  public:
    using Ptr = RCPtr<AddrList>;

    void add(const Addr &a)
    {
        if (!exists(a))
            push_back(a);
    }

    bool exists(const Addr &a) const
    {
        return std::ranges::find(*this, a) != end();
    }

#if 0
      void dump() const
      {
          OPENVPN_LOG("******* AddrList::dump");
          for (const auto& i : *this)
          {
              OPENVPN_LOG(i.to_string());
          }
      }
#endif
};
} // namespace openvpn::IP

#endif
