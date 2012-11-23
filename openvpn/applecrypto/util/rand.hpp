//
//  rand.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Wrap the Apple Cryptographic Random API defined in <Security/SecRandom.h>
// so that it can be used as the primary source of cryptographic entropy by
// the OpenVPN core.

#ifndef OPENVPN_APPLECRYPTO_UTIL_RAND_H
#define OPENVPN_APPLECRYPTO_UTIL_RAND_H

#include <Security/SecRandom.h>

#include <openvpn/common/rc.hpp>

namespace openvpn {
  class AppleRandom : public RC<thread_unsafe_refcount> {
  public:
    OPENVPN_EXCEPTION(rand_error_apple);

    typedef boost::intrusive_ptr<AppleRandom> Ptr;

    const char *name() const {
      return "AppleRandom";
    }

    void rand_bytes(unsigned char *buf, const size_t size)
    {
      if (!rand_bytes_noexcept(buf, size))
	throw rand_error_apple("rand_bytes");
    }

    // Like rand_bytes, but don't throw exception.
    // Return true on successs, false on fail.
    bool rand_bytes_noexcept(unsigned char *buf, const size_t size)
    {
      return SecRandomCopyBytes(kSecRandomDefault, size, buf) ? false : true;
    }
  };
}

#endif
