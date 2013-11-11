//
//  selftest.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
    os << "PolarSSL self test:" << std::endl;
    os << "  aes_self_test status=" << aes_self_test(verbose) << std::endl;
    os << "  sha1_self_test status=" << sha1_self_test(verbose) << std::endl;
    os << "  sha2_self_test status=" << sha2_self_test(verbose) << std::endl;
    os << "  sha4_self_test status=" << sha4_self_test(verbose) << std::endl;
    os << "  mpi_self_test status=" << mpi_self_test(verbose) << std::endl;
#else
    os << "PolarSSL self test: not compiled" << std::endl;
#endif
    return os.str();
  }
}

#endif
