//
//  free.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// deallocator for objects that were allocated by OpenSSL

#ifndef OPENVPN_OPENSSL_UTIL_FREE_H
#define OPENVPN_OPENSSL_UTIL_FREE_H

#include <openssl/crypto.h>

namespace openvpn {

  template <typename T>
  class OpenSSLFree {
  public:
    static void del(T* p)
    {
      OPENSSL_free (p);
    }
  };

}

#endif
