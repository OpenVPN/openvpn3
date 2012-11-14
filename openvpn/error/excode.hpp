//
//  excode.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_ERROR_EXCODE_H
#define OPENVPN_ERROR_EXCODE_H

#include <exception>

namespace openvpn {

  class ExceptionCode : public std::exception
  {
    enum {
      FATAL_FLAG = 0x80000000
    };

  public:
    ExceptionCode()
      : code_(0) {}
    ExceptionCode(const unsigned int code)
      : code_(code) {}
    ExceptionCode(const unsigned int code, const bool fatal)
      : code_(mkcode(code, fatal)) {}

    void set_code(const unsigned int code)
    {
      code_ = code;
    }

    void set_code(const unsigned int code, const bool fatal)
    {
      code_ = mkcode(code, fatal);
    }

    unsigned int code() const { return code_ & ~FATAL_FLAG; }
    bool fatal() const { return (code_ & FATAL_FLAG) != 0; }

    bool code_defined() const { return code_ != 0; }

    virtual ~ExceptionCode() throw() {}

  private:
    static unsigned int mkcode(const unsigned int code, const bool fatal)
    {
      unsigned int ret = code;
      if (fatal)
	ret |= FATAL_FLAG;
      return ret;
    }

    unsigned int code_;
  };

}
#endif
