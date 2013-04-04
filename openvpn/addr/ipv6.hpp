//
//  ipv6.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_ADDR_IPV6_H
#define OPENVPN_ADDR_IPV6_H

#include <cstring>           // for std::memcpy
#include <algorithm>         // for std::min

#include <boost/cstdint.hpp> // for boost::uint32_t
#include <boost/asio.hpp>
#include <boost/functional/hash.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/ostream.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/common/ffs.hpp>
#include <openvpn/addr/ipv4.hpp>

namespace openvpn {
  namespace IP {
    class Addr;
  }

  // Fundamental classes for representing an IPv6 IP address.

  namespace IPv6 {

    OPENVPN_EXCEPTION(ipv6_exception);

    class Addr // NOTE: must be union-legal, so default constructor does not initialize
    {
      friend class IP::Addr;

    public:
      enum { SIZE=128 };

      static Addr from_addr(const Addr& addr)
      {
	return addr;
      }

      static Addr from_string(const std::string& ipstr, const char *title = NULL)
      {
	boost::system::error_code ec;
	boost::asio::ip::address_v6 a = boost::asio::ip::address_v6::from_string(ipstr, ec);
	if (ec)
	  {
	    if (!title)
	      title = "";
	    OPENVPN_THROW(ipv6_exception, "error parsing " << title << " IPv6 address '" << ipstr << "' : " << ec.message());
	  }
	return from_asio(a);
      }

      std::string to_string() const
      {
	const boost::asio::ip::address_v6 a = to_asio();
	boost::system::error_code ec;
	std::string ret = a.to_string(ec);
	if (ec)
	  throw ipv6_exception("to_string");
	return ret;
      }

      std::string arpa() const
      {
	throw ipv6_exception("arpa() not implemented");
      }

      static Addr from_asio(const boost::asio::ip::address_v6& asio_addr)
      {
	Addr ret;
	union ipv6addr addr;
	addr.asio_bytes = asio_addr.to_bytes();
	network_to_host_order(&ret.u, &addr);
	ret.scope_id_ = asio_addr.scope_id();
	return ret;
      }

      boost::asio::ip::address_v6 to_asio() const
      {
	union ipv6addr addr;
	host_to_network_order(&addr, &u);
	return boost::asio::ip::address_v6(addr.asio_bytes, scope_id_);
      }

      static Addr from_zero()
      {
	Addr ret;
	ret.scope_id_ = 0;
	ret.zero();
	return ret;
      }

      static Addr from_zero_complement()
      {
	Addr ret;
	ret.scope_id_ = 0;
	ret.zero();
	ret.negate();
	return ret;
      }

      // build a netmask using given prefix_len
      static Addr netmask_from_prefix_len(const unsigned int prefix_len)
      {
	Addr ret;
	ret.scope_id_ = 0;
	ret.prefix_len_to_netmask(prefix_len);
	return ret;
      }

      // build a netmask using given extent
      static Addr netmask_from_extent(const unsigned int extent)
      {
	const int lb = find_last_set(extent - 1);
	return netmask_from_prefix_len(SIZE - lb);
      }

      Addr operator&(const Addr& other) const {
	Addr ret;
	ret.scope_id_ = scope_id_;
	ret.u.u64[0] = u.u64[0] & other.u.u64[0];
	ret.u.u64[1] = u.u64[1] & other.u.u64[1];
	return ret;
      }

      Addr operator|(const Addr& other) const {
	Addr ret;
	ret.scope_id_ = scope_id_;
	ret.u.u64[0] = u.u64[0] | other.u.u64[0];
	ret.u.u64[1] = u.u64[1] | other.u.u64[1];
	return ret;
      }

      Addr operator+(const long delta) const {
	Addr ret = *this;
	ret.u.u64[Endian::e2(0)] += delta;
	ret.u.u64[Endian::e2(1)] += (delta >= 0)
	  ? (ret.u.u64[Endian::e2(0)] < u.u64[Endian::e2(0)])
	  : -(ret.u.u64[Endian::e2(0)] > u.u64[Endian::e2(0)]);
	return ret;
      }

      Addr operator-(const long delta) const {
	return operator+(-delta);
      }

      long operator-(const Addr& other) const {
	ipv6addr res = u;
	res.u64[Endian::e2(0)] = u.u64[Endian::e2(0)] - other.u.u64[Endian::e2(0)];
	res.u64[Endian::e2(1)] = u.u64[Endian::e2(1)] - other.u.u64[Endian::e2(1)]
	  - (u.u64[Endian::e2(0)] < other.u.u64[Endian::e2(0)]);
	const long ret = res.u64[Endian::e2(0)];
	const boost::uint64_t backto = ret;
	if (res.u64[Endian::e2(1)] + (ret < 0) || backto != res.u64[Endian::e2(0)])
	  throw ipv6_exception("operator-() overflow");
	return ret;
      }

      Addr operator<<(const unsigned int shift) const {
	Addr ret = *this;
	shiftl128(ret.u.u64[Endian::e2(0)],
		  ret.u.u64[Endian::e2(1)],
		  shift);
	return ret;
      }

      Addr operator>>(const unsigned int shift) const {
	Addr ret = *this;
	shiftr128(ret.u.u64[Endian::e2(0)],
		  ret.u.u64[Endian::e2(1)],
		  shift);
	return ret;
      }

      Addr operator~() const {
	Addr ret;
	ret.scope_id_ = scope_id_;
	ret.u.u64[0] = ~u.u64[0];
	ret.u.u64[1] = ~u.u64[1];
	return ret;
      }

      // return the network that contains the current address
      Addr network_addr(const unsigned int prefix_len) const
      {
	return *this & netmask_from_prefix_len(prefix_len);
      }

      bool operator==(const Addr& other) const
      {
	return u.u64[0] == other.u.u64[0] && u.u64[1] == other.u.u64[1] && scope_id_ == other.scope_id_;
      }

      bool operator!=(const Addr& other) const
      {
	return !operator==(other);
      }

#define OPENVPN_IPV6_OPERATOR_REL(OP)					\
      bool operator OP(const Addr& other) const				\
      {									\
	if (u.u64[Endian::e2(1)] == other.u.u64[Endian::e2(1)])		\
	  {								\
	    if (u.u64[Endian::e2(0)] != other.u.u64[Endian::e2(0)])	\
	      return u.u64[Endian::e2(0)] OP other.u.u64[Endian::e2(0)]; \
	    else							\
	      return scope_id_ OP other.scope_id_;			\
	  }								\
	else								\
	  return u.u64[Endian::e2(1)] OP other.u.u64[Endian::e2(1)];	\
      }

      OPENVPN_IPV6_OPERATOR_REL(<)
      OPENVPN_IPV6_OPERATOR_REL(>)
      OPENVPN_IPV6_OPERATOR_REL(<=)
      OPENVPN_IPV6_OPERATOR_REL(>=)

#undef OPENVPN_IPV6_OPERATOR_REL

      bool unspecified() const
      {
	return all_zeros();
      }

      bool specified() const
      {
	return !unspecified();
      }

      bool all_ones() const
      {
	return u.u64[0] == ~(uint64_t)0 && u.u64[1] == ~(uint64_t)0;
      }

      // number of network bits in netmask,
      // throws exception if addr is not a netmask
      unsigned int prefix_len() const
      {
	int idx = -1;

	if (u.u32[Endian::e4(3)] != uint32_t(~0))
	  {
	    if (!u.u32[Endian::e4(0)] && !u.u32[Endian::e4(1)] && !u.u32[Endian::e4(2)])
	      idx = 0;
	  }
	else if (u.u32[Endian::e4(2)] != uint32_t(~0))
	  {
	    if (!u.u32[Endian::e4(0)] && !u.u32[Endian::e4(1)])
	      idx = 1;
	  }
	else if (u.u32[Endian::e4(1)] != uint32_t(~0))
	  {
	    if (!u.u32[Endian::e4(0)])
	      idx = 2;
	  }
	else
	  idx = 3;

	if (idx >= 0)
	  {
	    const int ret = IPv4::Addr::prefix_len_32(u.u32[Endian::e4rev(idx)]);
	    if (ret >= 0)
	      return ret + (idx<<5);
	  }
	throw ipv6_exception("malformed netmask");
      }

      // number of host bits in netmask
      unsigned int host_len() const
      {
	return SIZE - prefix_len();
      }

      // return the number of host addresses contained within netmask
      unsigned int extent() const
      {
	const unsigned int hl = host_len();
	if (hl < 32)
	  return 1 << hl;
	else if (hl == 32)
	  return 0;
	else
	  throw ipv6_exception("extent overflow");
      }

      std::size_t hashval() const
      {
	std::size_t seed = 0;
	boost::hash_combine(seed, u.u32[0]);
	boost::hash_combine(seed, u.u32[1]);
	boost::hash_combine(seed, u.u32[2]);
	boost::hash_combine(seed, u.u32[3]);
	return seed;
      }

#ifdef OPENVPN_IP_IMMUTABLE
    private:
#endif

      void negate()
      {
	u.u64[0] = ~u.u64[0];
	u.u64[1] = ~u.u64[1];
      }

      void zero()
      {
	u.u64[0] = 0;
	u.u64[1] = 0;
      }

      Addr& operator++()
      {
	const Addr a = *this + 1;
	u = a.u;
	return *this;
      }

    private:
      union ipv6addr {
	boost::uint64_t u64[2];
	boost::uint32_t u32[4]; // generally stored in host byte order
	unsigned char bytes[16];
	boost::asio::ip::address_v6::bytes_type asio_bytes;
      };

      bool all_zeros() const
      {
	return u.u64[0] == 0 && u.u64[1] == 0;
      }

      void prefix_len_to_netmask_unchecked(const unsigned int prefix_len)
      {
	if (prefix_len > 0)
	  {
	    const unsigned int pl = prefix_len - 1;
	    const boost::uint32_t mask = ~((1 << (31 - (pl & 31))) - 1);
	    switch (pl >> 5)
	      {
	      case 0:
		u.u32[Endian::e4(0)] = 0;
		u.u32[Endian::e4(1)] = 0;
		u.u32[Endian::e4(2)] = 0;
		u.u32[Endian::e4(3)] = mask;
		break;
	      case 1:
		u.u32[Endian::e4(0)] = 0;
		u.u32[Endian::e4(1)] = 0;
		u.u32[Endian::e4(2)] = mask;
		u.u32[Endian::e4(3)] = ~0;
		break;
	      case 2:
		u.u32[Endian::e4(0)] = 0;
		u.u32[Endian::e4(1)] = mask;
		u.u32[Endian::e4(2)] = ~0;
		u.u32[Endian::e4(3)] = ~0;
		break;
	      case 3:
		u.u32[Endian::e4(0)] = mask;
		u.u32[Endian::e4(1)] = ~0;
		u.u32[Endian::e4(2)] = ~0;
		u.u32[Endian::e4(3)] = ~0;
		break;
	      }
	  }
	else
	  zero();
      }

      void prefix_len_to_netmask(const unsigned int prefix_len)
      {
	if (prefix_len <= 128)
	  return prefix_len_to_netmask_unchecked(prefix_len);
	else
	  throw ipv6_exception("bad prefix len");
      }

      static void host_to_network_order(union ipv6addr *dest, const union ipv6addr *src)
      {
	dest->u32[0] = htonl(src->u32[Endian::e4rev(0)]);
	dest->u32[1] = htonl(src->u32[Endian::e4rev(1)]);
	dest->u32[2] = htonl(src->u32[Endian::e4rev(2)]);
	dest->u32[3] = htonl(src->u32[Endian::e4rev(3)]);
      }

      static void network_to_host_order(union ipv6addr *dest, const union ipv6addr *src)
      {
	dest->u32[0] = ntohl(src->u32[Endian::e4rev(0)]);
	dest->u32[1] = ntohl(src->u32[Endian::e4rev(1)]);
	dest->u32[2] = ntohl(src->u32[Endian::e4rev(2)]);
	dest->u32[3] = ntohl(src->u32[Endian::e4rev(3)]);
      }

      static void shiftl128(boost::uint64_t& low,
			    boost::uint64_t& high,
			    unsigned int shift)
      {
	if (shift == 0)
	  ;
	else if (shift <= 128)
	  {
	    if (shift >= 64)
	      {
		high = low;
		low = 0;
		shift -= 64;
	      }
	    if (shift < 64)
	      {
		high = (high << shift) | (low >> (64-shift));
		low = (low << shift);
	      }
	    else // shift == 64
	      high = 0;
	  }
	else
	  throw ipv6_exception("l-shift too large");
      }

      static void shiftr128(boost::uint64_t& low,
			    boost::uint64_t& high,
			    unsigned int shift)
      {
	if (shift == 0)
	  ;
	else if (shift <= 128)
	  {
	    if (shift >= 64)
	      {
		low = high;
		high = 0;
		shift -= 64;
	      }
	    if (shift < 64)
	      {
		low = (low >> shift) | (high << (64-shift));
		high = (high >> shift);
	      }
	    else // shift == 64
	      low = 0;
	  }
	else
	  throw ipv6_exception("r-shift too large");
      }

      union ipv6addr u;
      unsigned int scope_id_;
    };

    OPENVPN_OSTREAM(Addr, to_string)

    inline std::size_t hash_value(const Addr& addr)
    {
      return addr.hashval();
    }
  }
} // namespace openvpn

#endif // OPENVPN_ADDR_IPV6_H
