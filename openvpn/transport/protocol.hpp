//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

#ifndef OPENVPN_TRANSPORT_PROTOCOL_H
#define OPENVPN_TRANSPORT_PROTOCOL_H

#include <string>

#include <boost/cstdint.hpp> // for boost::uint32_t, etc.
#include <boost/algorithm/string.hpp> // for boost::algorithm::to_lower, ends_with

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn {
// A class that encapsulates a transport protocol.
  class Protocol
  {
  public:
    enum Type {
      NONE,
      UDPv4,
      TCPv4,
      UDPv6,
      TCPv6,
      UDP=UDPv4,
      TCP=TCPv4,
    };

    Protocol() : type_(NONE) {}
    explicit Protocol(const Type t) : type_(t) {}
    Type operator()() const { return type_; }

    bool defined() const { return type_ != NONE; }

    void reset() { type_ = NONE; }

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

    bool transport_match(const Protocol& other) const
    {
      return transport_proto() == other.transport_proto();
    }

    unsigned int extra_transport_bytes() const
    {
      return is_tcp() ? sizeof(boost::uint16_t) : 0;
    }

    void mod_addr_version(const IP::Addr& addr)
    {
      switch (addr.version())
	{
	case IP::Addr::UNSPEC:
	  break;
	case IP::Addr::V4:
	  if (is_udp())
	    type_ = UDPv4;
	  else if (is_tcp())
	    type_ = TCPv4;
	  break;
	case IP::Addr::V6:
	  if (is_udp())
	    type_ = UDPv6;
	  else if (is_tcp())
	    type_ = TCPv6;
	  break;
	}
    }

    static Protocol parse(const std::string& str, const bool allow_client_suffix)
    {
      Protocol ret;
      std::string s = str;
      boost::algorithm::to_lower(s);
      if (s == "adaptive")
	return ret;
      if (allow_client_suffix && boost::algorithm::ends_with(s, "-client"))
	s = s.substr(0, s.length()-7);
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

    int transport_proto() const
    {
      switch (type_)
	{
	case UDPv4:
	  return 0;
	case TCPv4:
	  return 1;
	case UDPv6:
	  return 0;
	case TCPv6:
	  return 1;
	default:
	  return -1;
	}
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

    const char *str_client(const bool force_ipv4) const
    {
      switch (type_)
	{
	case UDPv4:
	  return "UDPv4";
	case TCPv4:
	  return "TCPv4_CLIENT";
	case UDPv6:
	  return force_ipv4 ? "UDPv4" : "UDPv6";
	case TCPv6:
	  return force_ipv4 ? "TCPv4_CLIENT" : "TCPv6_CLIENT";
	default:
	  return "UNDEF_PROTO";
	}
    }

  private:
    Type type_;
  };
} // namespace openvpn

#endif // OPENVPN_TRANSPORT_PROTOCOL_H
