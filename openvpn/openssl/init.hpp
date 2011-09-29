#ifndef OPENVPN_OPENSSL_INIT_H
#define OPENVPN_OPENSSL_INIT_H

#include <boost/asio/ssl/detail/openssl_init.hpp>

namespace openvpn {

  // Instantiate this object to ensure openssl is initialised.
  typedef boost::asio::ssl::detail::openssl_init<> openssl_init;

} // namespace openvpn

#endif // OPENVPN_OPENSSL_INIT_H
