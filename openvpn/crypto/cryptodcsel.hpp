//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

// Select appropriate OpenVPN protocol data channel implementation

#ifndef OPENVPN_CRYPTO_CRYPTODCSEL_H
#define OPENVPN_CRYPTO_CRYPTODCSEL_H

#include <openvpn/common/exception.hpp>
#include <openvpn/crypto/cryptodc.hpp>
#include <openvpn/crypto/crypto_chm.hpp>

namespace openvpn {

  OPENVPN_EXCEPTION(crypto_dc_select);

  template <typename CRYPTO_API>
  class CryptoDCSelect : public CryptoDCFactory<CRYPTO_API>
  {
  public:
    typedef boost::intrusive_ptr<CryptoDCSelect> Ptr;

    CryptoDCSelect(const Frame::Ptr& frame_arg,
		   const PRNG::Ptr& prng_arg)
      : frame(frame_arg),
	prng(prng_arg)
    {
    }

    virtual typename CryptoDCContext<CRYPTO_API>::Ptr new_obj(const CryptoAlgs::Type cipher,
							      const CryptoAlgs::Type digest)
    {
      // fixme -- handle AEAD modes as well
      return new CryptoContextCHM<CRYPTO_API>(cipher, digest, frame, prng);
    }

  private:
    Frame::Ptr frame;
    PRNG::Ptr prng;
  };

}

#endif
