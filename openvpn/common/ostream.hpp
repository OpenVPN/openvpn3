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

// A helper macro for setting up an arbitrary class
// to support stringstream concatenation using <<

#ifndef OPENVPN_COMMON_OSTREAM_H
#define OPENVPN_COMMON_OSTREAM_H

#include <ostream>
#include <string>

#define OPENVPN_OSTREAM(TYPE, METH)                             \
    template <typename Elem, typename Traits>                   \
    std::basic_ostream<Elem, Traits> &operator<<(               \
        std::basic_ostream<Elem, Traits> &os, const TYPE &addr) \
    {                                                           \
        os << addr.METH();                                      \
        return os;                                              \
    }

#endif // OPENVPN_COMMON_OSTREAM_H
