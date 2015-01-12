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

#ifndef OPENVPN_AUTH_AUTHCERT_H
#define OPENVPN_AUTH_AUTHCERT_H

#include <string>
#include <sstream>
#include <cstring>

#include <boost/cstdint.hpp>       // for boost::uint32_t, uint64_t
#include <boost/static_assert.hpp> // for BOOST_STATIC_ASSERT

#include <openvpn/common/rc.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/socktypes.hpp> // for ntohl

namespace openvpn {

    struct AuthCert : public RC<thread_unsafe_refcount>
    {
      typedef boost::intrusive_ptr<AuthCert> Ptr;

      AuthCert()
      {
	std::memset(issuer_fp, 0, sizeof(issuer_fp));
	sn = -1;
      }

      template <typename T>
      T issuer_fp_prefix() const
      {
	BOOST_STATIC_ASSERT(sizeof(T) == 4 || sizeof(T) == 8);
	if (sizeof(T) == 8)
	  return (T(ntohl(*(uint32_t *)&issuer_fp[0])) << 32) | T(ntohl(*(uint32_t *)&issuer_fp[4]));
	else // sizeof(T) == 4
	  return T(ntohl(*(uint32_t *)&issuer_fp[0]));
      }

      bool operator==(const AuthCert& other) const
      {
	return cn == other.cn && sn == other.sn && !std::memcmp(issuer_fp, other.issuer_fp, sizeof(issuer_fp));
      }

      bool operator!=(const AuthCert& other) const
      {
	return !operator==(other);
      }

      std::string to_string() const
      {
	std::ostringstream os;
	os << "CN=" << cn
	   << " SN=" << sn
	   << " ISSUER_FP=" << render_hex(issuer_fp, sizeof(issuer_fp));
	return os.str();
      }

      std::string cn;                // common name
      long sn;                       // serial number
      unsigned char issuer_fp[20];   // issuer cert fingerprint
    };
}

#endif
