#ifndef OPENVPN_TRANSPORT_PROTOCOL_H
#define OPENVPN_TRANSPORT_PROTOCOL_H

#include <boost/cstdint.hpp> // for boost::uint32_t, etc.

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

    bool is_udp() const { return type_ == UDPv4 || type_ == UDPv6; }
    bool is_tcp() const { return type_ == TCPv4 || type_ == TCPv6; }

    bool is_reliable() const { return is_tcp(); }

    unsigned int extra_transport_bytes() const
    {
      return is_tcp() ? sizeof(boost::uint16_t) : 0;
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
