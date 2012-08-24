//
//  cryptoinit.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_INIT_CRYPTOINIT_H
#define OPENVPN_INIT_CRYPTOINIT_H

#ifdef USE_OPENSSL
#include <openvpn/openssl/util/init.hpp>
#endif

namespace openvpn {

  class crypto_init
  {
#if defined(USE_OPENSSL)
    openssl_init openssl_init_;
#endif    
  };

}

#endif
