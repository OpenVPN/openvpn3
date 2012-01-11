#ifndef OPENVPN_ADDR_IPV4_H
#define OPENVPN_ADDR_IPV4_H

#include <boost/cstdint.hpp> // for boost::uint32_t
#include <boost/asio.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/ostream.hpp>

namespace openvpn {
  namespace IP {
    class Addr;
  }

  namespace IPv4 {

    OPENVPN_SIMPLE_EXCEPTION(ipv4_render_exception);
    OPENVPN_EXCEPTION(ipv4_parse_exception);

    class Addr // NOTE: must be union-legal, so default constructor does not initialize
    {
      friend class IP::Addr;

    public:
      typedef boost::uint32_t base_type;

      static Addr from_uint32(const base_type addr)
      {
	Addr ret;
	ret.u.addr = addr;
	return ret;
      }

      static Addr from_string(const std::string& ipstr, const char *title = NULL)
      {
	boost::system::error_code ec;
	boost::asio::ip::address_v4 a = boost::asio::ip::address_v4::from_string(ipstr, ec);
	if (ec)
	  {
	    if (!title)
	      title = "";
	    OPENVPN_THROW(ipv4_parse_exception, "error parsing " << title << " IPv4 address '" << ipstr << "' : " << ec.message());
	  }
	return from_asio(a);
      }

      std::string to_string() const
      {
	const boost::asio::ip::address_v4 a = to_asio();
	boost::system::error_code ec;
	std::string ret = a.to_string(ec);
	if (ec)
	  throw ipv4_render_exception();
	return ret;
      }

      static Addr from_asio(const boost::asio::ip::address_v4& asio_addr)
      {
	Addr ret;
	ret.u.addr = asio_addr.to_ulong();
	return ret;
      }

      boost::asio::ip::address_v4 to_asio() const
      {
	return boost::asio::ip::address_v4(u.addr);
      }

      Addr operator&(const Addr& other) const {
	Addr ret;
	ret.u.addr = u.addr & other.u.addr;
	return ret;
      }

      Addr operator|(const Addr& other) const {
	Addr ret;
	ret.u.addr = u.addr | other.u.addr;
	return ret;
      }

      bool unspecified() const
      {
	return u.addr == 0;
      }

    private:
      union {
	boost::uint32_t addr;
	unsigned char bytes[4];
      } u;
    };

    OPENVPN_OSTREAM(Addr, to_string)
  }
} // namespace openvpn

#endif // OPENVPN_ADDR_IPV4_H
