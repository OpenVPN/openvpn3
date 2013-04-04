//
//  ipv4.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_ADDR_IPV4_H
#define OPENVPN_ADDR_IPV4_H

#include <cstring> // for std::memcpy
#include <sstream>

#include <boost/cstdint.hpp> // for boost::uint32_t
#include <boost/asio.hpp>
#include <boost/functional/hash.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/endian.hpp>
#include <openvpn/common/ostream.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/common/ffs.hpp>

namespace openvpn {
  namespace IP {
    class Addr;
  }

  // Fundamental classes for representing an IPv4 IP address.

  namespace IPv4 {

    OPENVPN_EXCEPTION(ipv4_exception);

    class Addr // NOTE: must be union-legal, so default constructor does not initialize
    {
      friend class IP::Addr;

    public:
      enum { SIZE=32 };

      typedef boost::uint32_t base_type;

      static Addr from_addr(const Addr& addr)
      {
	return addr;
      }

      static Addr from_uint32(const base_type addr) // host byte order
      {
	Addr ret;
	ret.u.addr = addr;
	return ret;
      }

      static Addr from_bytes(const unsigned char *bytes) // host byte order
      {
	Addr ret;
	std::memcpy(ret.u.bytes, bytes, 4);
	return ret;
      }

      static Addr from_zero()
      {
	Addr ret;
	ret.zero();
	return ret;
      }

      static Addr from_zero_complement()
      {
	Addr ret;
	ret.zero();
	ret.negate();
	return ret;
      }

      // build a netmask using given prefix_len
      static Addr netmask_from_prefix_len(const unsigned int prefix_len)
      {
	Addr ret;
	ret.u.addr = prefix_len_to_netmask(prefix_len);
	return ret;
      }

      // build a netmask using given extent
      static Addr netmask_from_extent(const unsigned int extent)
      {
	const int lb = find_last_set(extent - 1);
	return netmask_from_prefix_len(SIZE - lb);
      }

      static Addr from_string(const std::string& ipstr, const char *title = NULL)
      {
	boost::system::error_code ec;
	boost::asio::ip::address_v4 a = boost::asio::ip::address_v4::from_string(ipstr, ec);
	if (ec)
	  {
	    if (!title)
	      title = "";
	    OPENVPN_THROW(ipv4_exception, "error parsing " << title << " IPv4 address '" << ipstr << "' : " << ec.message());
	  }
	return from_asio(a);
      }

      std::string to_string() const
      {
	const boost::asio::ip::address_v4 a = to_asio();
	boost::system::error_code ec;
	std::string ret = a.to_string(ec);
	if (ec)
	  throw ipv4_exception("to_string");
	return ret;
      }

      std::string arpa() const
      {
	std::ostringstream os;
	os << int(u.bytes[Endian::e4(0)]) << '.'
	   << int(u.bytes[Endian::e4(1)]) << '.'
	   << int(u.bytes[Endian::e4(2)]) << '.'
	   << int(u.bytes[Endian::e4(3)]) << ".in-addr.arpa";
	return os.str();
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

      Addr operator+(const long delta) const {
	Addr ret;
	ret.u.addr = u.addr + delta;
	return ret;
      }

      Addr operator-(const long delta) const {
	return operator+(-delta);
      }

      long operator-(const Addr& other) const {
	return long(u.addr) - long(other.u.addr);
      }

      Addr operator<<(const unsigned int shift) const {
	Addr ret;
	ret.u.addr = u.addr << shift;
	return ret;
      }

      Addr operator>>(const unsigned int shift) const {
	Addr ret;
	ret.u.addr = u.addr >> shift;
	return ret;
      }

      Addr operator~() const {
	Addr ret;
	ret.u.addr = ~u.addr;
	return ret;
      }

      // return the network that contains the current address
      Addr network_addr(const unsigned int prefix_len) const
      {
	Addr ret;
	ret.u.addr = u.addr & prefix_len_to_netmask(prefix_len);
	return ret;
      }

      bool operator==(const Addr& other) const
      {
	return u.addr == other.u.addr;
      }

      bool operator!=(const Addr& other) const
      {
	return u.addr != other.u.addr;
      }

      bool operator<(const Addr& other) const
      {
	return u.addr < other.u.addr;
      }

      bool operator>(const Addr& other) const
      {
	return u.addr > other.u.addr;
      }

      bool operator<=(const Addr& other) const
      {
	return u.addr <= other.u.addr;
      }

      bool operator>=(const Addr& other) const
      {
	return u.addr >= other.u.addr;
      }

      bool unspecified() const
      {
	return u.addr == 0;
      }

      bool specified() const
      {
	return !unspecified();
      }

      bool all_ones() const
      {
	return ~u.addr == 0;
      }

      // number of network bits in netmask,
      // throws exception if addr is not a netmask
      unsigned int prefix_len() const
      {
	const int ret = prefix_len_32(u.addr);
	if (ret >= 0)
	  return ret;
	else
	  throw ipv4_exception("malformed netmask");
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
	  throw ipv4_exception("extent overflow");
      }

      // convert netmask in addr to prefix_len, will return -1 on error
      static int prefix_len_32(const uint32_t addr)
      {
	if (addr == uint32_t(~0))
	  return 32;
	else if (addr == 0)
	  return 0;
	else
	  {
	    unsigned int high = 32;
	    unsigned int low = 1;
	    for (unsigned int i = 0; i < 5; ++i)
	      {
		const unsigned int mid = (high + low) / 2;
		const IPv4::Addr::base_type test = prefix_len_to_netmask_unchecked(mid);
		if (addr == test)
		  return mid;
		else if (addr > test)
		  low = mid;
		else
		  high = mid;
	      }
	    return -1;
	  }
      }

      std::size_t hashval() const
      {
	std::size_t seed = 0;
	boost::hash_combine(seed, u.addr);
	return seed;
      }

#ifdef OPENVPN_IP_IMMUTABLE
    private:
#endif

      void negate()
      {
	u.addr = ~u.addr;
      }

      void zero()
      {
	u.addr = 0;
      }

      Addr& operator++()
      {
	++u.addr;
	return *this;
      }

    private:
      static base_type prefix_len_to_netmask_unchecked(const unsigned int prefix_len)
      {
	if (prefix_len)
	  return ~((1 << (32 - prefix_len)) - 1);
	else
	  return 0;
      }

      static base_type prefix_len_to_netmask(const unsigned int prefix_len)
      {
	if (prefix_len <= 32)
	  return prefix_len_to_netmask_unchecked(prefix_len);
	else
	  throw ipv4_exception("bad prefix len");
      }

      union {
	base_type addr; // host byte order
	unsigned char bytes[4];
      } u;
    };

    OPENVPN_OSTREAM(Addr, to_string)

    inline std::size_t hash_value(const Addr& addr)
    {
      return addr.hashval();
    }
  }
} // namespace openvpn

#endif // OPENVPN_ADDR_IPV4_H
