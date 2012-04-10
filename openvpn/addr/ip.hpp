#ifndef OPENVPN_ADDR_IP_H
#define OPENVPN_ADDR_IP_H

#include <string>

#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/ostream.hpp>
#include <openvpn/addr/ipv4.hpp>
#include <openvpn/addr/ipv6.hpp>

namespace openvpn {
  namespace IP {

    OPENVPN_SIMPLE_EXCEPTION(ip_addr_unspecified);
    OPENVPN_SIMPLE_EXCEPTION(ip_addr_version_inconsistency);
    OPENVPN_SIMPLE_EXCEPTION(ip_render_exception);
    OPENVPN_EXCEPTION(ip_parse_exception);

    class Addr
    {
    public:
      enum Version { UNSPEC, V4, V6 };

      Addr()
      {
	ver = UNSPEC;
      }

      static std::string validate(const std::string& ipstr, const char *title = NULL)
      {
	Addr a = from_string(ipstr, title);
	return a.to_string();
      }

      static Addr from_string(const std::string& ipstr, const char *title = NULL)
      {
	boost::system::error_code ec;
	boost::asio::ip::address a = boost::asio::ip::address::from_string(ipstr, ec);
	if (ec)
	  {
	    if (!title)
	      title = "";
	    OPENVPN_THROW(ip_parse_exception, "error parsing " << title << " IP address '" << ipstr << "' : " << ec.message());
	  }
	return from_asio(a);
      }

      static Addr from_ipv4(const IPv4::Addr& addr)
      {
	Addr a;
	a.ver = V4;
	a.u.v4 = addr;
	return a;
      }

      static Addr from_ipv6(const IPv6::Addr& addr)
      {
	Addr a;
	a.ver = V6;
	a.u.v6 = addr;
	return a;
      }

      static Addr from_zero(Version v)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::from_zero());
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::from_zero());
	else
	  throw ip_addr_unspecified();
      }

      static Addr from_zero_complement(Version v)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::from_zero_complement());
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::from_zero_complement());
	else
	  throw ip_addr_unspecified();
      }

      static Addr netmask_from_prefix_len(Version v, const unsigned int prefix_len)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::netmask_from_prefix_len(prefix_len));
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::netmask_from_prefix_len(prefix_len));
	else
	  throw ip_addr_unspecified();
      }

      std::string to_string() const
      {
	if (ver != UNSPEC)
	  {
	    const boost::asio::ip::address a = to_asio();
	    boost::system::error_code ec;
	    std::string ret = a.to_string(ec);
	    if (ec)
	      throw ip_render_exception();
	    return ret;
	  }
	else
	  return "UNSPEC";
      }

      static Addr from_asio(const boost::asio::ip::address& addr)
      {
	if (addr.is_v4())
	  {
	    Addr a;
	    a.ver = V4;
	    a.u.v4 = IPv4::Addr::from_asio(addr.to_v4());
	    return a;
	  }
	else if (addr.is_v6())
	  {
	    Addr a;
	    a.ver = V6;
	    a.u.v6 = IPv6::Addr::from_asio(addr.to_v6());
	    return a;
	  }
	else
	  throw ip_addr_unspecified();
      }

      boost::asio::ip::address to_asio() const
      {
	switch (ver)
	  {
	  case V4:
	    return boost::asio::ip::address_v4(u.v4.to_asio());
	  case V6:
	    return boost::asio::ip::address_v6(u.v6.to_asio());
	  default:
	    throw ip_addr_unspecified();
	  }
      }

      Addr operator&(const Addr& other) const {
	if (ver != other.ver)
	  throw ip_addr_version_inconsistency();
	switch (ver)
	  {
	  case V4:
	    {
	      Addr ret;
	      ret.ver = V4;
	      ret.u.v4 = u.v4 & other.u.v4;
	      return ret;
	    }
	  case V6:
	    {
	      Addr ret;
	      ret.ver = V6;
	      ret.u.v6 = u.v6 & other.u.v6;
	      return ret;
	    }
	  default:
	    throw ip_addr_unspecified();
	  }
      }

      Addr operator|(const Addr& other) const {
	if (ver != other.ver)
	  throw ip_addr_version_inconsistency();
	switch (ver)
	  {
	  case V4:
	    {
	      Addr ret;
	      ret.ver = V4;
	      ret.u.v4 = u.v4 | other.u.v4;
	      return ret;
	    }
	  case V6:
	    {
	      Addr ret;
	      ret.ver = V6;
	      ret.u.v6 = u.v6 | other.u.v6;
	      return ret;
	    }
	  default:
	    throw ip_addr_unspecified();
	  }
      }

      bool operator==(const Addr& other) const
      {
	switch (ver)
	  {
	  case V4:
	    if (ver == other.ver)
	      return u.v4 == other.u.v4;
	    break;
	  case V6:
	    if (ver == other.ver)
	      return u.v6 == other.u.v6;
	    break;
	  case UNSPEC:
	    return other.ver == UNSPEC;
	  }
	return false;
      }

      Addr& operator++()
      {
	switch (ver)
	  {
	  case V4:
	    ++u.v4;
	    break;
	  case V6:
	    ++u.v6;
	    break;
	  default:
	    break;
	  }
	return *this;
      }

      void reset_ipv4_from_uint32(const IPv4::Addr::base_type addr)
      {
	ver = V4;
	u.v4 = IPv4::Addr::from_uint32(addr);
      }

      bool unspecified() const
      {
	switch (ver)
	  {
	  case V4:
	    return u.v4.unspecified();
	  case V6:
	    return u.v6.unspecified();
	  default:
	    return true;
	  }
      }

      const char *version_string() const
      {
	switch (ver)
	  {
	  case V4:
	    return "v4";
	  case V6:
	    return "v6";
	  default:
	    return "v?";
	  }
      }

      Version version() const { return ver; }

      void verify_version_consistency(const Addr& other) const
      {
	if (ver != other.ver)
	  throw ip_addr_version_inconsistency();
      }

      unsigned int prefix_len() const
      {
	switch (ver)
	  {
	  case V4:
	    return u.v4.prefix_len();
	  case V6:
	    return u.v6.prefix_len();
	  default:
	    return true;
	  }
      }

    private:
      friend std::size_t hash_value(const Addr&);

      union {
	IPv4::Addr v4;
	IPv6::Addr v6;
      } u;

      Version ver;
    };

    OPENVPN_OSTREAM(Addr, to_string)

    inline std::size_t hash_value(const Addr& addr)
    {
      switch (addr.ver)
	{
	case Addr::V4:
	  return hash_value(addr.u.v4);
	case Addr::V6:
	  return hash_value(addr.u.v6);
	default:
	  return 0;
	}
    }
  }
} // namespace openvpn

#endif // OPENVPN_ADDR_IP_H
