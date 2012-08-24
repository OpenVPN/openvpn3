//
//  error.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_POLARSSL_UTIL_ERROR_H
#define OPENVPN_POLARSSL_UTIL_ERROR_H

#include <string>

#include <polarssl/error.h>

#include <openvpn/common/exception.hpp>

namespace openvpn {

  // string exception class
  class PolarSSLException : public std::exception
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

    explicit PolarSSLException(const std::string& error_text, const int polarssl_errnum)
    {
      errnum = polarssl_errnum;
      errtxt = "PolarSSL: " + error_text + " : " + polarssl_errtext(polarssl_errnum);
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
