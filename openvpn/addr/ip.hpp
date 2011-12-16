#ifndef OPENVPN_ADDR_IP_H
#define OPENVPN_ADDR_IP_H

#include <boost/asio.hpp>

#include <openvpn/common/exception.hpp>

namespace openvpn {

  OPENVPN_EXCEPTION(ip_address_error);

  std::string validate_ip_address(const char *title, const std::string ip_addr)
  {
    boost::system::error_code ec;
    const boost::asio::ip::address addr = boost::asio::ip::address::from_string(ip_addr, ec);
    if (!ec)
      {
	std::string ret = addr.to_string(ec);
	if (!ec)
	  return ret;
      }
    OPENVPN_THROW(ip_address_error, "error validating " << title << " IP address '" << ip_addr << "' : " << ec.message());
  }

} // namespace openvpn

#endif // OPENVPN_ADDR_IP_H
