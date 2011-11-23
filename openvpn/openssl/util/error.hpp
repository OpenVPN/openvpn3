#ifndef OPENVPN_OPENSSL_SSLERR_H
#define OPENVPN_OPENSSL_SSLERR_H

#include <string>
#include <openssl/err.h>

#include <openvpn/common/exception.hpp>

namespace openvpn {

  // string exception class
  class OpenSSLException : public std::exception
  {
  public:
    OPENVPN_EXCEPTION(ssl_exception_index);

    enum {
      MAX_ERRORS = 8
    };

    OpenSSLException()
    {
      ssl_err = -1;
      init_error("OpenSSL");
    }

    explicit OpenSSLException(const std::string error_text)
    {
      ssl_err = -1;
      init_error(error_text.c_str());
    }

    explicit OpenSSLException(const int ssl_error)
    {
      init_ssl_error(ssl_error, "OpenSSL");
    }

    explicit OpenSSLException(const int ssl_error, const std::string error_text)
    {
      init_ssl_error(ssl_error, error_text.c_str());
    }

    virtual const char* what() const throw() { return errtxt.c_str(); }
    std::string what_str() const { return errtxt; }

    size_t len() const { return n_err; }
    unsigned long operator[](const size_t i) const
    {
      if (i < n_err)
	return errstack[i];
      else
	throw ssl_exception_index();
    }

    int ssl_error() const { return ssl_err; }

    virtual ~OpenSSLException() throw() {}

    static const char *ssl_error_text(const int ssl_error, bool *unknown = NULL)
    {
      switch (ssl_error)
	{
	case SSL_ERROR_NONE:
	  return "SSL_ERROR_NONE";
	case SSL_ERROR_ZERO_RETURN:
	  return "SSL_ERROR_ZERO_RETURN";
	case SSL_ERROR_WANT_READ:
	  return "SSL_ERROR_WANT_READ";
	case SSL_ERROR_WANT_WRITE:
	  return "SSL_ERROR_WANT_WRITE";
	case SSL_ERROR_WANT_CONNECT:
	  return "SSL_ERROR_WANT_CONNECT";
	case SSL_ERROR_WANT_ACCEPT:
	  return "SSL_ERROR_WANT_ACCEPT";
	case SSL_ERROR_WANT_X509_LOOKUP:
	  return "SSL_ERROR_WANT_X509_LOOKUP";
	case SSL_ERROR_SYSCALL:
	  return "SSL_ERROR_SYSCALL";
	case SSL_ERROR_SSL:
	  return "SSL_ERROR_SSL";
	default:
	  if (unknown)
	    *unknown = true;
	  return "(unknown SSL error)";
	}
    }

  private:
    void init_error(const char *error_text)
    {
      const char *prefix = ": ";
      std::ostringstream tmp;
      char buf[256];

      tmp << error_text;

      n_err = 0;
      while (unsigned long err = ERR_get_error())
	{
	  if (n_err < MAX_ERRORS)
	    errstack[n_err++] = err;
	  ERR_error_string_n(err, buf, sizeof(buf));
	  tmp << prefix << buf;
	  prefix = " / ";
	}
      errtxt = tmp.str();
    }

    void init_ssl_error(const int ssl_error, const char *error_text)
    {
      bool unknown = false;
      ssl_err = ssl_error;
      const char *text = ssl_error_text(ssl_error, &unknown);
      if (unknown || ssl_error == SSL_ERROR_SYSCALL || ssl_error == SSL_ERROR_SSL)
	{
	  init_error(error_text);
	  errtxt += " (";
	  errtxt += text;
	  errtxt += ")";
	}
      else
	{
	  errtxt = error_text;
	  errtxt += ": ";
	  errtxt += text;
	}
    }

    size_t n_err;
    unsigned long errstack[MAX_ERRORS];
    std::string errtxt;
    int ssl_err;
  };

  // return an OpenSSL error string

  inline std::string openssl_error()
  {
    OpenSSLException err;
    return err.what_str();
  }

  inline std::string openssl_error(const int ssl_error)
  {
    OpenSSLException err(ssl_error);
    return err.what_str();
  }

} // namespace openvpn

#endif // OPENVPN_OPENSSL_SSLERR_H
