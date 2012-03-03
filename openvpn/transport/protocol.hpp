#ifndef OPENVPN_TRANSPORT_PROTOCOL_H
#define OPENVPN_TRANSPORT_PROTOCOL_H

#include <string>

#include <boost/cstdint.hpp> // for boost::uint32_t, etc.
#include <boost/algorithm/string.hpp> // for boost::algorithm::to_lower

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn {
  class Protocol
  {
  public:
    enum Type {
      NONE,
      UDPv4,
      TCPv4,
      UDPv6,
      TCPv6,
    };

    Protocol() : type_(NONE) {}
    explicit Protocol(const Type t) : type_(t) {}
    Type operator()() const { return type_; }

    bool defined() const { return type_ != NONE; }

    bool is_udp() const { return type_ == UDPv4 || type_ == UDPv6; }
    bool is_tcp() const { return type_ == TCPv4 || type_ == TCPv6; }

    bool is_reliable() const { return is_tcp(); }

    bool operator==(const Protocol& other) const
    {
      return type_ == other.type_;
    }

    bool operator!=(const Protocol& other) const
    {
      return type_ != other.type_;
    }

    unsigned int extra_transport_bytes() const
    {
      return is_tcp() ? sizeof(boost::uint16_t) : 0;
    }

    static Protocol parse(const std::string& str)
    {
      Protocol ret;
      std::string s = str;
      boost::algorithm::to_lower(s);
      if (s.length() >= 3)
	{
	  const std::string s1 = s.substr(0, 3);
	  const std::string s2 = s.substr(3);
	  if (s2 == "" || s2 == "4" || s2 == "v4")
	    {
	      if (s1 == "udp")
		ret.type_ = UDPv4;
	      else if (s1 == "tcp")
		ret.type_ = TCPv4;
	    }
	  else if (s2 == "6" || s2 == "v6")
	    {
	      if (s1 == "udp")
		ret.type_ = UDPv6;
	      else if (s1 == "tcp")
		ret.type_ = TCPv6;
	    }
	}
      if (ret.type_ == NONE)
	OPENVPN_THROW(option_error, "error parsing protocol: " << s);
      return ret;
    }

    const char *str() const
    {
      switch (type_)
	{
	case UDPv4:
	  return "UDPv4";
	case TCPv4:
	  return "TCPv4";
	case UDPv6:
	  return "UDPv6";
	case TCPv6:
	  return "TCPv6";
	default:
	  return "UNDEF_PROTO";
	}
    }

    const char *str_client() const
    {
      switch (type_)
	{
	case UDPv4:
	  return "UDPv4";
	case TCPv4:
	  return "TCPv4_CLIENT";
	case UDPv6:
	  return "UDPv6";
	case TCPv6:
	  return "TCPv6_CLIENT";
	default:
	  return "UNDEF_PROTO";
	}
    }

  private:
    Type type_;
  };
} // namespace openvpn

#endif // OPENVPN_TRANSPORT_PROTOCOL_H
