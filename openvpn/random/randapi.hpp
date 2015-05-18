//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

// API for random number implementations.

#ifndef OPENVPN_POLARSSL_UTIL_RANDAPI_H
#define OPENVPN_POLARSSL_UTIL_RANDAPI_H

#include <string>

#include <openvpn/common/size.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {

  class RandomAPI : public RC<thread_unsafe_refcount>
  {
  public:
    typedef RCPtr<RandomAPI> Ptr;

    // Random algorithm name
    virtual std::string name() const = 0;

    // Fill buffer with random bytes
    virtual void rand_bytes(unsigned char *buf, size_t size) = 0;

    // Like rand_bytes, but don't throw exception.
    // Return true on successs, false on fail.
    virtual bool rand_bytes_noexcept(unsigned char *buf, size_t size) = 0;

    template <typename T>
    void rand_fill(T& obj)
    {
      rand_bytes(reinterpret_cast<unsigned char *>(&obj), sizeof(T));
    }
  };

}

#endif
