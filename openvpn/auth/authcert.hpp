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

#include <openvpn/common/rc.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/binprefix.hpp>

namespace openvpn {

    struct AuthCert : public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<AuthCert> Ptr;

      AuthCert()
      {
	std::memset(issuer_fp, 0, sizeof(issuer_fp));
	sn = -1;
      }

      bool defined() const
      {
	return sn >= 0;
      }

      bool cn_defined() const
      {
	return !cn.empty();
      }

      template <typename T>
      T issuer_fp_prefix() const
      {
	return bin_prefix<T>(issuer_fp);
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
	   << " ISSUER_FP=" << issuer_fp_str(false);
	return os.str();
      }

      std::string issuer_fp_str(const bool openssl_fmt) const
      {
	if (openssl_fmt)
	  return render_hex_sep(issuer_fp, sizeof(issuer_fp), ':', true);
	else
	  return render_hex(issuer_fp, sizeof(issuer_fp), false);
      }

      std::string normalize_cn() const // remove trailing "_AUTOLOGIN" from AS certs
      {
	if (string::ends_with(cn, "_AUTOLOGIN"))
	  return cn.substr(0, cn.length() - 10);
	else
	  return cn;
      }

      std::string cn;                // common name
      long sn;                       // serial number
      unsigned char issuer_fp[20];   // issuer cert fingerprint
    };
}

#endif
