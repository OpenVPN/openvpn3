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

// Define null logging macros

#ifndef OPENVPN_LOG_LOGNULL_H
#define OPENVPN_LOG_LOGNULL_H

#define OPENVPN_LOG(args)

// like OPENVPN_LOG but no trailing newline
#define OPENVPN_LOG_NTNL(args)

#define OPENVPN_LOG_STRING(str)

#endif
