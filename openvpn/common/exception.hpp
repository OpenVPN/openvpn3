//
//  exception.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Basic exception handling.  Allow exception classes for specific errors
// to be easily defined, and allow exceptions to be thrown with a consise
// syntax that allows stringstream concatenation using <<

#ifndef OPENVPN_COMMON_EXCEPTION_H
#define OPENVPN_COMMON_EXCEPTION_H

#include <string>
#include <sstream>
#include <exception>

#include <boost/algorithm/string.hpp> // for boost::algorithm::starts_with
#include <boost/system/error_code.hpp>

#include <openvpn/common/stringize.hpp> // for OPENVPN_STRINGIZE

#ifdef OPENVPN_DEBUG_EXCEPTION
  // well-known preprocessor hack to get __FILE__:__LINE__ rendered as a string
# define OPENVPN_FILE_LINE "/" __FILE__ ":" OPENVPN_STRINGIZE(__LINE__)
#else
# define OPENVPN_FILE_LINE
#endif

namespace openvpn {
  // returns a string describing a boost::system error code
  template <typename ErrorCode>
  inline std::string errinfo(ErrorCode err)
  {
    boost::system::error_code e(err, boost::system::system_category());
    return e.message();
  }

  // string exception class, where the exception is described by a std::string
  class Exception : public std::exception
  {
  public:
    Exception(const std::string& err) : err_(err) {}
    virtual const char* what() const throw() { return err_.c_str(); }
    const std::string& err() const { return err_; }
    virtual ~Exception() throw() {}

    void add_label(const std::string& label)
    {
      err_ = label + ": " + err_;
    }

    void remove_label(const std::string& label)
    {
      const std::string head = label + ": ";
      if (boost::algorithm::starts_with(err_, head))
	err_ = err_.substr(head.length());
    }

  private:
    std::string err_;
  };

  // define a simple custom exception class with no extra info
# define OPENVPN_SIMPLE_EXCEPTION(C) \
  class C : public std::exception { \
  public: \
    virtual const char* what() const throw() { return #C OPENVPN_FILE_LINE; } \
  }

  // define a simple custom exception class with no extra info that inherits from a custom base
# define OPENVPN_SIMPLE_EXCEPTION_INHERIT(B, C)	\
  class C : public B { \
  public: \
    virtual const char* what() const throw() { return #C OPENVPN_FILE_LINE; } \
  }

  // define a custom exception class that allows extra info
# define OPENVPN_EXCEPTION(C) \
  class C : public openvpn::Exception { \
  public: \
    C() : openvpn::Exception(#C OPENVPN_FILE_LINE) {} \
    C(std::string err) : openvpn::Exception(#C OPENVPN_FILE_LINE ": " + err) {} \
  }

  // define a custom exception class that allows extra info, but does not emit a tag
# define OPENVPN_UNTAGGED_EXCEPTION(C) \
  class C : public openvpn::Exception { \
  public: \
    C(std::string err) : openvpn::Exception(err) {} \
  }

  // define a custom exception class that allows extra info, and inherits from a custom base
# define OPENVPN_EXCEPTION_INHERIT(B, C) \
  class C : public B { \
  public: \
    C() : B(#C OPENVPN_FILE_LINE) {} \
    C(std::string err) : B(#C OPENVPN_FILE_LINE ": " + err) {} \
  }

  // define a custom exception class that allows extra info, and inherits from a custom base,
  // but does not emit a tag
# define OPENVPN_UNTAGGED_EXCEPTION_INHERIT(B, C) \
  class C : public B { \
  public: \
    C(std::string err) : B(err) {} \
  }

  // throw an Exception with stringstream concatenation allowed
# define OPENVPN_THROW_EXCEPTION(stuff) \
  do { \
    std::ostringstream _ovpn_exc; \
    _ovpn_exc << stuff; \
    throw openvpn::Exception(_ovpn_exc.str()); \
  } while (0)

  // throw an OPENVPN_EXCEPTION class with stringstream concatenation allowed
# define OPENVPN_THROW(exc, stuff) \
  do { \
    std::ostringstream _ovpn_exc; \
    _ovpn_exc << stuff; \
    throw exc(_ovpn_exc.str()); \
  } while (0)

  // properly rethrow an exception that might be derived from Exception
  inline void throw_ref(const std::exception& e)
  {
    const Exception* ex = dynamic_cast<const Exception*>(&e);
    if (ex)
      throw *ex;
    else
      throw e;
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_EXCEPTION_H
