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

#if defined(USE_OPENSSL)
#include <openvpn/openssl/util/engine.hpp>
#endif

#if 0
extern "C" {
  void OPENSSL_cpuid_setup();
}
#endif

namespace openvpn {

  void setup_crypto_engine(const std::string& engine)
  {
#if defined(USE_OPENSSL)
    openssl_setup_engine(engine);
#endif
  }

#if 0
  OPENSSL_cpuid_setup();
#endif
}

#endif
