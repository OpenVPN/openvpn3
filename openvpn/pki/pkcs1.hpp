//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_PKI_PKCS1_H
#define OPENVPN_PKI_PKCS1_H

namespace openvpn {
  namespace PKCS1 {
    // from http://www.ietf.org/rfc/rfc3447.txt
    namespace DigestPrefix { // CONST GLOBAL
      static const unsigned char MD2[] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
					   0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
					   0x02, 0x02, 0x05, 0x00, 0x04, 0x10 };
      static const unsigned char MD5[] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
					   0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
					   0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
      static const unsigned char SHA1[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
					    0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
					    0x00, 0x04, 0x14 };
      static const unsigned char SHA256[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
					      0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
					      0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
					      0x20 };
      static const unsigned char SHA384[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
					      0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
					      0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
					      0x30 };
      static const unsigned char SHA512[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
					      0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
					      0x04, 0x02, 0x03, 0x05, 0x00, 0x04,
					      0x40 };
    }
  }
}

#endif
