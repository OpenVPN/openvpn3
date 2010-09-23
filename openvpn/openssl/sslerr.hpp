#ifndef OPENVPN_CRYPTO_SSLERR_H
#define OPENVPN_CRYPTO_SSLERR_H

#include <openssl/err.h>
#include <boost/exception/all.hpp>

namespace openvpn {

// return an OpenSSL error string
inline
std::string
openssl_error(void)
{
  std::ostringstream tmp;
  char buf[256];

  tmp << "OpenSSL";

  const char *prefix = ": ";
  while (unsigned long err = ERR_get_error())
    {
      ERR_error_string_n(err, buf, sizeof(buf));
      tmp << prefix << buf;
      prefix = " / ";
    }
  return tmp.str();
}

inline
std::string
openssl_ssl_error(const int sslerr)
{
  switch (sslerr)
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
      return openssl_error() + " (SSL_ERROR_SYSCALL)";
    case SSL_ERROR_SSL:
      return openssl_error() + " (SSL_ERROR_SSL)";
    default:
      return openssl_error() + " (unknown SSL error)";
    }
}

// OpenSSL error object for use with BOOST_THROW_EXCEPTION

typedef boost::error_info<struct errinfo_openssl_,std::string> errinfo_openssl_exc;

inline
errinfo_openssl_exc
errinfo_openssl(void)
{
  return errinfo_openssl_exc(openssl_error());
}

} // namespace openvpn

#endif // OPENVPN_CRYPTO_SSLERR_H
