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

#ifndef OPENVPN_ADDR_IP_H
#define OPENVPN_ADDR_IP_H

#include <string>

#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/ostream.hpp>
#include <openvpn/addr/ipv4.hpp>
#include <openvpn/addr/ipv6.hpp>
#include <openvpn/addr/iperr.hpp>

namespace openvpn {
  // This is our fundamental IP address class that handles IPv4 or IPv6
  // IP addresses.  It is implemented as a discriminated union of IPv4::Addr
  // and IPv6::Addr.
  namespace IP {

    OPENVPN_EXCEPTION(ip_exception);

    class Addr
    {
    public:
      enum Version { UNSPEC, V4, V6 };

      enum VersionSize {
	V4_SIZE = IPv4::Addr::SIZE,
	V6_SIZE = IPv6::Addr::SIZE,
      };

      Addr(const Addr& other, const char *title = NULL, Version required_version = UNSPEC)
	: ver(other.ver)
      {
	if (required_version != UNSPEC && required_version != ver)
	  throw ip_exception(internal::format_error(other.to_string(), title, version_string_static(required_version), "wrong IP version"));
	switch (ver)
	  {
	  case V4:
	    u.v4 = other.u.v4;
	    break;
	  case V6:
	    u.v6 = other.u.v6;
	    break;
	  default:
	    break;
	  }
      }

      Addr(const std::string& ipstr, const char *title = NULL, Version required_version = UNSPEC)
      {
	*this = from_string(ipstr, title, required_version);
      }

      static std::string validate(const std::string& ipstr, const char *title = NULL, Version required_version = UNSPEC)
      {
	Addr a = from_string(ipstr, title, required_version);
	return a.to_string();
      }

      static bool is_valid(const std::string& ipstr)
      {
	// fast path -- rule out validity if invalid chars
	for (size_t i = 0; i < ipstr.length(); ++i)
	  {
	    const char c = ipstr[i];
	    if (!((c >= '0' && c <= '9')
		  || (c >= 'a' && c <= 'f')
		  || (c >= 'A' && c <= 'F')
		  || (c == '.' || c == ':' || c == '%')))
	      return false;
	  }

	// slow path
	{
	  boost::system::error_code ec;
	  boost::asio::ip::address::from_string(ipstr, ec);
	  return !ec;
	}
      }

      static Addr from_string(const std::string& ipstr, const char *title = NULL, Version required_version = UNSPEC)
      {
	boost::system::error_code ec;
	boost::asio::ip::address a = boost::asio::ip::address::from_string(ipstr, ec);
	if (ec)
	  throw ip_exception(internal::format_error(ipstr, title, "", ec));
	const Addr ret = from_asio(a);
	if (required_version != UNSPEC && required_version != ret.ver)
	  throw ip_exception(internal::format_error(ipstr, title, version_string_static(required_version), "wrong IP version"));
	return ret;
      }

      static Addr from_hex(Version v, const std::string& s)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::from_hex(s));
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::from_hex(s));
	else
	  throw ip_exception("address unspecified");
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

      const IPv4::Addr& to_ipv4() const
      {
	if (ver == V4)
	  return u.v4;
	else
	  throw ip_exception("address is not IPv4");
      }

      const IPv6::Addr& to_ipv6() const
      {
	if (ver == V6)
	  return u.v6;
	else
	  throw ip_exception("address is not IPv6");
      }

      static Addr from_ulong(Version v, unsigned long ul)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::from_ulong(ul));
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::from_ulong(ul));
	else
	  throw ip_exception("address unspecified");
      }

      // return *this as a ulong, will raise exception on overflow
      unsigned long to_ulong() const
      {
	if (ver == V4)
	  return u.v4.to_ulong();
	else if (ver == V6)
	  return u.v6.to_ulong();
	else
	  throw ip_exception("address unspecified");
      }

      static Addr from_long(Version v, long ul)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::from_long(ul));
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::from_long(ul));
	else
	  throw ip_exception("address unspecified");
      }

      // return *this as a long, will raise exception on overflow
      long to_long() const
      {
	if (ver == V4)
	  return u.v4.to_long();
	else if (ver == V6)
	  return u.v6.to_long();
	else
	  throw ip_exception("address unspecified");
      }

      // construct an address where all bits are zero
      static Addr from_zero(Version v)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::from_zero());
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::from_zero());
	else
	  throw ip_exception("address unspecified");
      }

      // construct an address where all bits are zero
      static Addr from_one(Version v)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::from_one());
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::from_one());
	else
	  throw ip_exception("address unspecified");
      }

      // construct an address where all bits are one
      static Addr from_zero_complement(Version v)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::from_zero_complement());
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::from_zero_complement());
	else
	  throw ip_exception("address unspecified");
      }

      // build a netmask using given prefix_len
      static Addr netmask_from_prefix_len(Version v, const unsigned int prefix_len)
      {
	if (v == V4)
	  return from_ipv4(IPv4::Addr::netmask_from_prefix_len(prefix_len));
	else if (v == V6)
	  return from_ipv6(IPv6::Addr::netmask_from_prefix_len(prefix_len));
	else
	  throw ip_exception("address unspecified");
      }

      // build a netmask using *this as extent
      Addr netmask_from_extent() const
      {
	if (ver == V4)
	  return from_ipv4(u.v4.netmask_from_extent());
	else if (ver == V6)
	  return from_ipv6(u.v6.netmask_from_extent());
	else
	  throw ip_exception("address unspecified");
      }

      std::string to_string() const
      {
	if (ver != UNSPEC)
	  {
	    const boost::asio::ip::address a = to_asio();
	    boost::system::error_code ec;
	    std::string ret = a.to_string(ec);
	    if (ec)
	      throw ip_exception("to_string");
	    return ret;
	  }
	else
	  return "UNSPEC";
      }

      std::string to_hex() const
      {
	if (ver == V4)
	  return u.v4.to_hex();
	else if (ver == V6)
	  return u.v6.to_hex();
	else
	  throw ip_exception("address unspecified");
      }

      std::string arpa() const
      {
	if (ver == V4)
	  return u.v4.arpa();
	else if (ver == V6)
	  return u.v6.arpa();
	else
	  throw ip_exception("address unspecified");
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
	  throw ip_exception("address unspecified");
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
	    throw ip_exception("address unspecified");
	  }
      }

      Addr operator+(const long delta) const {
	switch (ver)
	  {
	  case V4:
	    {
	      Addr ret;
	      ret.ver = V4;
	      ret.u.v4 = u.v4 + delta;
	      return ret;
	    }
	  case V6:
	    {
	      Addr ret;
	      ret.ver = V6;
	      ret.u.v6 = u.v6 + delta;
	      return ret;
	    }
	  default:
	    throw ip_exception("address unspecified");
	  }
      }

      Addr operator-(const long delta) const {
	return operator+(-delta);
      }

#define OPENVPN_IP_OPERATOR_BINOP(OP)		       \
      Addr operator OP (const Addr& other) const {     \
	if (ver != other.ver)                          \
	  throw ip_exception("version inconsistency"); \
	switch (ver)                                   \
	  {                                            \
	  case V4:                                     \
	    {                                          \
	      Addr ret;                                \
	      ret.ver = V4;                            \
	      ret.u.v4 = u.v4 OP other.u.v4;           \
	      return ret;                              \
	    }                                          \
	  case V6:                                     \
	    {                                          \
	      Addr ret;                                \
	      ret.ver = V6;                            \
	      ret.u.v6 = u.v6 OP other.u.v6;           \
	      return ret;                              \
	    }                                          \
	  default:                                     \
	    throw ip_exception("address unspecified"); \
	  }                                            \
      }

      OPENVPN_IP_OPERATOR_BINOP(+)
      OPENVPN_IP_OPERATOR_BINOP(-)
      OPENVPN_IP_OPERATOR_BINOP(*)
      OPENVPN_IP_OPERATOR_BINOP(/)
      OPENVPN_IP_OPERATOR_BINOP(%)
      OPENVPN_IP_OPERATOR_BINOP(&)
      OPENVPN_IP_OPERATOR_BINOP(|)

#undef OPENVPN_IP_OPERATOR_BINOP

      Addr operator<<(const unsigned int shift) const {
	switch (ver)
	  {
	  case V4:
	    {
	      Addr ret;
	      ret.ver = V4;
	      ret.u.v4 = u.v4 << shift;
	      return ret;
	    }
	  case V6:
	    {
	      Addr ret;
	      ret.ver = V6;
	      ret.u.v6 = u.v6 << shift;
	      return ret;
	    }
	  default:
	    throw ip_exception("address unspecified");
	  }
      }

      Addr operator>>(const unsigned int shift) const {
	switch (ver)
	  {
	  case V4:
	    {
	      Addr ret;
	      ret.ver = V4;
	      ret.u.v4 = u.v4 >> shift;
	      return ret;
	    }
	  case V6:
	    {
	      Addr ret;
	      ret.ver = V6;
	      ret.u.v6 = u.v6 >> shift;
	      return ret;
	    }
	  default:
	    throw ip_exception("address unspecified");
	  }
      }

      Addr operator~() const {
	switch (ver)
	  {
	  case V4:
	    {
	      Addr ret;
	      ret.ver = V4;
	      ret.u.v4 = ~u.v4;
	      return ret;
	    }
	  case V6:
	    {
	      Addr ret;
	      ret.ver = V6;
	      ret.u.v6 = ~u.v6;
	      return ret;
	    }
	  default:
	    throw ip_exception("address unspecified");
	  }
      }

      Addr network_addr(const unsigned int prefix_len) const {
	switch (ver)
	  {
	  case V4:
	    {
	      Addr ret;
	      ret.ver = V4;
	      ret.u.v4 = u.v4.network_addr(prefix_len);
	      return ret;
	    }
	  case V6:
	    {
	      Addr ret;
	      ret.ver = V6;
	      ret.u.v6 = u.v6.network_addr(prefix_len);
	      return ret;
	    }
	  default:
	    throw ip_exception("address unspecified");
	  }
      }

      bool operator==(const Addr& other) const
      {
	switch (ver)
	  {
	  case UNSPEC:
	    return other.ver == UNSPEC;
	  case V4:
	    if (ver == other.ver)
	      return u.v4 == other.u.v4;
	    break;
	  case V6:
	    if (ver == other.ver)
	      return u.v6 == other.u.v6;
	    break;
	  }
	return false;
      }

      bool operator!=(const Addr& other) const
      {
	return !operator==(other);
      }

#define OPENVPN_IP_OPERATOR_REL(OP)		\
      bool operator OP(const Addr& other) const \
      {						\
	if (ver == other.ver)			\
	  {					\
	    switch (ver)			\
	      {					\
	      case V4:				\
		return u.v4 OP other.u.v4;	\
	      case V6:				\
		return u.v6 OP other.u.v6;	\
	      default:				\
		return false;			\
	      }					\
	  }					\
	else if (ver OP other.ver)		\
	  return true;				\
	else					\
	  return false;				\
      }

      OPENVPN_IP_OPERATOR_REL(<)
      OPENVPN_IP_OPERATOR_REL(>)
      OPENVPN_IP_OPERATOR_REL(<=)
      OPENVPN_IP_OPERATOR_REL(>=)

#undef OPENVPN_IP_OPERATOR_REL

      bool unspecified() const
      {
	return all_zeros();
      }

      bool specified() const
      {
	return !unspecified();
      }

      bool all_zeros() const
      {
	switch (ver)
	  {
	  case V4:
	    return u.v4.all_zeros();
	  case V6:
	    return u.v6.all_zeros();
	  default:
	    return true;
	  }
      }

      bool all_ones() const
      {
	switch (ver)
	  {
	  case V4:
	    return u.v4.all_ones();
	  case V6:
	    return u.v6.all_ones();
	  default:
	    return false;
	  }
      }

      bool defined() const
      {
	return ver != UNSPEC;
      }

      const char *version_string() const
      {
	return version_string_static(ver);
      }

      static const char *version_string_static(Version ver)
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

      bool is_compatible(const Addr& other) const
      {
	return ver == other.ver;
      }

      void verify_version_consistency(const Addr& other) const
      {
	if (!is_compatible(other))
	  throw ip_exception("version inconsistency");
      }

      // throw exception if address is not a valid netmask
      void validate_netmask()
      {
	prefix_len();
      }

      // number of network bits in netmask,
      // throws exception if addr is not a netmask
      unsigned int prefix_len() const
      {
	switch (ver)
	  {
	  case V4:
	    return u.v4.prefix_len();
	  case V6:
	    return u.v6.prefix_len();
	  default:
	    throw ip_exception("address unspecified");
	  }
      }

      // number of host bits in netmask
      unsigned int host_len() const
      {
	switch (ver)
	  {
	  case V4:
	    return u.v4.host_len();
	  case V6:
	    return u.v6.host_len();
	  default:
	    throw ip_exception("address unspecified");
	  }
      }

      // return the number of host addresses contained within netmask
      Addr extent_from_netmask() const
      {
	switch (ver)
	  {
	  case V4:
	    return from_ipv4(u.v4.extent_from_netmask());
	  case V6:
	    return from_ipv6(u.v6.extent_from_netmask());
	  default:
	    throw ip_exception("address unspecified");
	  }
      }

      // address size in bits
      unsigned int size() const
      {
	return version_size(ver);
      }

      // address size in bits of particular IP version
      static unsigned int version_size(Version v)
      {
	if (v == V4)
	  return IPv4::Addr::SIZE;
	else if (v == V6)
	  return IPv6::Addr::SIZE;
	else
	  return 0;
      }

      std::size_t hashval() const
      {
	std::size_t seed = 0;
	switch (ver)
	  {
	  case Addr::V4:
	    boost::hash_combine(seed, 4);
	    boost::hash_combine(seed, u.v4);
	    break;
	  case Addr::V6:
	    boost::hash_combine(seed, 6);
	    boost::hash_combine(seed, u.v6);
	    break;
	  default:
	    break;
	  }
	return seed;
      }

#ifdef OPENVPN_IP_IMMUTABLE
    private:
#endif

      Addr()
	: ver(UNSPEC)
      {
      }

      void reset()
      {
	ver = UNSPEC;
      }

      Addr& operator=(const Addr& other)
      {
	switch (ver = other.ver)
	  {
	  case V4:
	    u.v4 = other.u.v4;
	    break;
	  case V6:
	    u.v6 = other.u.v6;
	    break;
	  default:
	    break;
	  }
	return *this;
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

    private:
      union {
	IPv4::Addr v4;
	IPv6::Addr v6;
      } u;

      Version ver;
    };

    OPENVPN_OSTREAM(Addr, to_string)

    inline std::size_t hash_value(const Addr& addr)
    {
      return addr.hashval();
    }
  }
} // namespace openvpn

#endif // OPENVPN_ADDR_IP_H
