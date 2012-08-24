//
//  engineinit.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_INIT_ENGINEINIT_H
#define OPENVPN_INIT_ENGINEINIT_H

#include <string>

#if defined(USE_OPENSSL)
#include <openvpn/openssl/util/engine.hpp>
#endif

namespace openvpn {

  void setup_crypto_engine(const std::string& engine)
  {
#if defined(USE_OPENSSL)
    openssl_setup_engine(engine);
#endif
  }

}

#endif
