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

// Non-cryptographic random number generator

#ifndef OPENVPN_RANDOM_MTRAND_H
#define OPENVPN_RANDOM_MTRAND_H

#include <random>

namespace openvpn {

  class RandomIntBase
  {
  public:
    typedef std::mt19937::result_type type;

    RandomIntBase(type seed)
      : rng_(seed)
    {
    }

    RandomIntBase()
      : rng_(gen_seed())
    {
    }

    type randrange(const type end)
    {
      return rng_() % end;
    }

    type rand()
    {
      return rng_();
    }

    std::mt19937& operator()()
    {
      return rng_;
    }

    static std::random_device::result_type gen_seed()
    {
      std::random_device rd;
      return rd();
    }

  private:
    std::mt19937 rng_;
  };

}

#endif
