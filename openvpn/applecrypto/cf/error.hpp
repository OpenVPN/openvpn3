//
//  error.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_APPLECRYPTO_CF_ERROR_H
#define OPENVPN_APPLECRYPTO_CF_ERROR_H

#include <string>

#include <CoreFoundation/CFBase.h>

#include <openvpn/common/exception.hpp>

namespace openvpn {

  // string exception class
  class CFException : public std::exception
  {
  public:
    CFException(const std::string& text)
    {
      errtxt = text;
    }

    CFException(const std::string& text, const OSStatus status)
    {
      set_errtxt(text, status);
    }

    virtual const char* what() const throw() { return errtxt.c_str(); }
    std::string what_str() const { return errtxt; }

    virtual ~CFException() throw() {}

  private:
    void set_errtxt(const std::string& text, const OSStatus status)
    {
      std::ostringstream s;
      s << text << ": OSX Error code=" << status;
      errtxt = s.str();
    }

    std::string errtxt;
  };

} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_CF_ERROR_H
