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

// A general purpose container for OpenVPN protocol encrypt and decrypt objects.

#ifndef OPENVPN_CRYPTO_CRYPTO_H
#define OPENVPN_CRYPTO_CRYPTO_H

#include <openvpn/crypto/encrypt.hpp>
#include <openvpn/crypto/decrypt.hpp>

namespace openvpn {

  template <typename RAND_API, typename CRYPTO_API>
  struct CryptoContext
  {
    Encrypt<RAND_API, CRYPTO_API> encrypt;
    Decrypt<CRYPTO_API> decrypt;
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_CRYPTO_H
