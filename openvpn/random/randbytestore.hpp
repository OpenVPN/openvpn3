//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#ifndef OPENVPN_RANDOM_RANDBYTESTORE_H
#define OPENVPN_RANDOM_RANDBYTESTORE_H

#include <openvpn/common/size.hpp>

namespace openvpn {

template <typename RAND_TYPE>
class RandomByteStore
{
  public:
    unsigned char get_byte(RAND_TYPE &rng)
    {
        if (n_bytes == 0)
        {
            res = rng();
            n_bytes = sizeof(res);
        }
        const unsigned char ret = static_cast<unsigned char>(res);
        res >>= 8;
        --n_bytes;
        return ret;
    }

    template <typename T>
    void fill(T &obj, RAND_TYPE &rng)
    {
        unsigned char *data = reinterpret_cast<unsigned char *>(&obj);
        for (size_t i = 0; i < sizeof(obj); ++i)
            data[i] = get_byte(rng);
    }

  private:
    typename RAND_TYPE::result_type res = 0;
    unsigned int n_bytes = 0;
};

} // namespace openvpn
#endif
