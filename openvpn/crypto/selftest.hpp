//
//  crypto.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// A general purpose container for OpenVPN protocol encrypt and decrypt objects.

#ifndef OPENVPN_CRYPTO_SELFTEST_H
#define OPENVPN_CRYPTO_SELFTEST_H

#include <string>

#ifdef USE_OPENSSL
//#include <openvpn/openssl/util/selftest.hpp>
#endif

#ifdef USE_APPLE_SSL
//#include <openvpn/applecrypto/util/selftest.hpp>
#endif

#ifdef USE_POLARSSL
#include <openvpn/polarssl/util/selftest.hpp>
#endif

#ifdef USE_POLARSSL_APPLE_HYBRID
//#include <openvpn/applecrypto/util/selftest.hpp>
#include <openvpn/polarssl/util/selftest.hpp>
#endif

namespace openvpn {
  namespace SelfTest {
    inline std::string crypto_self_test()
    {
      std::string ret;
#     ifdef USE_OPENSSL
        //ret += crypto_self_test_openssl();
#     endif
#     ifdef USE_APPLE_SSL
        //ret += crypto_self_test_apple();
#     endif
#     if defined(USE_POLARSSL) || defined(USE_POLARSSL_APPLE_HYBRID)
        ret += crypto_self_test_polarssl();
#     endif
      return ret;
    }
  }
} // namespace openvpn

#endif // OPENVPN_CRYPTO_CRYPTO_H
