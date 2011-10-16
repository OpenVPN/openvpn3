#ifndef OPENVPN_COMMON_ADDR_H
#define OPENVPN_COMMON_ADDR_H

#include <boost/asio/ip/detail/endpoint.hpp>

namespace openvpn {
  // encapsulates IP version, address, and port (but not protocol)
  typedef boost::asio::ip::detail::endpoint endpoint;
} // namespace openvpn

#endif // OPENVPN_COMMON_ADDR_H
