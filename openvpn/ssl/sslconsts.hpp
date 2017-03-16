//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

#ifndef OPENVPN_SSL_SSLCONSTS_H
#define OPENVPN_SSL_SSLCONSTS_H

namespace openvpn {
  namespace SSLConst {

    // Special return values from SSL read/write methods
    enum {
      // Indicates that no cleartext data is available now (until
      // more ciphertext is pushed into the SSL engine).
      SHOULD_RETRY = -1,

      // Return value from read_cleartext indicating that peer
      // has sent a Close Notify message.
      PEER_CLOSE_NOTIFY = -2,
    };

    // SSL config flags
    enum {
      // Show SSL status and cert chain in verify method
      LOG_VERIFY_STATUS=(1<<0),

      // Disable peer verification
      NO_VERIFY_PEER=(1<<1),

      // Enable SNI (Server Name Indication) when hostname is provided
      ENABLE_SNI=(1<<2),

      // [server only] Don't automatically fail connections on
      // bad peer cert.  Succeed the connection, but pass the
      // fail status data via AuthCert so the higher layers
      // can handle it.
      DEFERRED_CERT_VERIFY=(1<<3),
    };

  }
}

#endif
