//
//  engineinit.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// process-wide initialization for underlying cryptographic engines

#ifndef OPENVPN_INIT_ENGINEINIT_H
#define OPENVPN_INIT_ENGINEINIT_H

#include <string>

#include <openvpn/common/arch.hpp>

#if defined(USE_OPENSSL)
#include <openvpn/openssl/util/engine.hpp>
#endif

#if defined(USE_MINICRYPTO) && (defined(OPENVPN_ARCH_x86_64) || defined(OPENVPN_ARCH_i386))
extern "C" {
  void OPENSSL_cpuid_setup();
}
#endif

namespace openvpn {

  void setup_crypto_engine(const std::string& engine)
  {
#if defined(USE_OPENSSL)
    openssl_setup_engine(engine);
#elif defined(USE_MINICRYPTO) && (defined(OPENVPN_ARCH_x86_64) || defined(OPENVPN_ARCH_i386))
    OPENSSL_cpuid_setup();
#endif
  }

}
#endif
