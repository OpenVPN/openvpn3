#ifndef OPENVPN_APPLECRYPTO_CF_ERROR_H
#define OPENVPN_APPLECRYPTO_CF_ERROR_H

#include <openvpn/common/exception.hpp>

namespace openvpn {

  // string exception class
  class CFException : public std::exception
  {
  public:
    CFException(const OSStatus status)
    {
      set_errtxt(status, NULL);
    }

    CFException(const OSStatus status, const std::string& text)
    {
      set_errtxt(status, &text);
    }

    virtual const char* what() const throw() { return errtxt.c_str(); }
    std::string what_str() const { return errtxt; }

    virtual ~CFException() throw() {}

  private:
    void set_errtxt(const OSStatus status, const std::string* text)
    {
      std::ostringstream s;
      if (text)
	s << *text << ": ";
      s << "OSX Error code=" << status;
      errtxt = s.str();
    }

    std::string errtxt;
  };

} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_CF_ERROR_H
