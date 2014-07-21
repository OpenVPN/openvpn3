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

// PolarSSL exception class that allows a PolarSSL error code
// to be represented.

#ifndef OPENVPN_POLARSSL_UTIL_ERROR_H
#define OPENVPN_POLARSSL_UTIL_ERROR_H

#include <string>

#include <polarssl/pem.h>
#include <polarssl/error.h>

#include <openvpn/common/exception.hpp>
#include <openvpn/error/error.hpp>
#include <openvpn/error/excode.hpp>

namespace openvpn {

  // string exception class
  class PolarSSLException : public ExceptionCode
  {
  public:
    PolarSSLException()
    {
      errnum = 0;
      errtxt = "PolarSSL";
    }

    explicit PolarSSLException(const std::string& error_text)
    {
      errnum = 0;
      errtxt = "PolarSSL: " + error_text;
    }

    explicit PolarSSLException(const std::string& error_text, const Error::Type code, const bool fatal)
      : ExceptionCode(code, fatal)
    {
      errnum = 0;
      errtxt = "PolarSSL: " + error_text;
    }

    explicit PolarSSLException(const std::string& error_text, const int polarssl_errnum)
    {
      errnum = polarssl_errnum;
      errtxt = "PolarSSL: " + error_text + " : " + polarssl_errtext(polarssl_errnum);

      // for certain PolarSSL errors, translate them to an OpenVPN error code,
      // so they can be propagated up to the higher levels (such as UI level)
      switch (errnum) {
      case POLARSSL_ERR_X509_CERT_VERIFY_FAILED:
	set_code(Error::CERT_VERIFY_FAIL, true);
	break;
      case POLARSSL_ERR_PK_PASSWORD_REQUIRED:
      case POLARSSL_ERR_PK_PASSWORD_MISMATCH:
	set_code(Error::PEM_PASSWORD_FAIL, true);
	break;
      case POLARSSL_ERR_SSL_BAD_HS_PROTOCOL_VERSION:
	set_code(Error::TLS_VERSION_MIN, true);
	break;
      }
    }

    virtual const char* what() const throw() { return errtxt.c_str(); }
    std::string what_str() const { return errtxt; }

    int get_errnum() const { return errnum; }

    virtual ~PolarSSLException() throw() {}

    static std::string polarssl_errtext(int errnum)
    {
      char buf[256];
      polarssl_strerror(errnum, buf, sizeof(buf));
      return buf;
    }

  private:
    std::string errtxt;
    int errnum;
  };
}

#endif
