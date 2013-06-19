//
//  error.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
#if 0 // As of PolarSSL 1.2.8, it appears that these codes are no longer returned
      case POLARSSL_ERR_PEM_PASSWORD_REQUIRED:
      case POLARSSL_ERR_PEM_PASSWORD_MISMATCH:
#endif
      case POLARSSL_ERR_X509_PASSWORD_REQUIRED:
      case POLARSSL_ERR_X509_PASSWORD_MISMATCH:
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
      error_strerror(errnum, buf, sizeof(buf));
      return buf;
    }

  private:
    std::string errtxt;
    int errnum;
  };
}

#endif
