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

// Call various PolarSSL self-test functions

#ifndef OPENVPN_POLARSSL_UTIL_SELFTEST_H
#define OPENVPN_POLARSSL_UTIL_SELFTEST_H

#include <sstream>

#include <polarssl/config.h>
#include <polarssl/cipher.h>
#include <polarssl/aes.h>

namespace openvpn {
  inline std::string crypto_self_test_polarssl()
  {
    std::ostringstream os;
#ifdef POLARSSL_SELF_TEST
    const int verbose = 1;
    os << "PolarSSL self test (tests return 0 if successful):" << std::endl;
    os << "  aes_self_test status=" << aes_self_test(verbose) << std::endl;
    os << "  sha1_self_test status=" << sha1_self_test(verbose) << std::endl;
    os << "  sha256_self_test status=" << sha256_self_test(verbose) << std::endl;
    os << "  sha512_self_test status=" << sha512_self_test(verbose) << std::endl;
    os << "  mpi_self_test status=" << mpi_self_test(verbose) << std::endl;
#else
    os << "PolarSSL self test: not compiled" << std::endl;
#endif
    return os.str();
  }
}

#endif
