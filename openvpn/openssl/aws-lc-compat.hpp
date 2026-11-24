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

#pragma once

#define BIOerr(f, r) OPENSSL_PUT_ERROR(BIO, r)

#define SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED SSL_R_TLSV1_ALERT_CERTIFICATE_REQUIRED
