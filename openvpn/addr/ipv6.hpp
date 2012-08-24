//
//  ipv6.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_ADDR_IPV6_H
#define OPENVPN_ADDR_IPV6_H

#include <cstring> // for std::memcpy

#include <boost/cstdint.hpp> // for boost::uint32_t
#include <boost/asio.hpp>
#include <boost/functional/hash.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/ostream.hpp>

namespace openvpn {
  namespace IP {
    class Addr;
  }

  namespace IPv6 {

    OPENVPN_SIMPLE_EXCEPTION(ipv6_render_exception);
    OPENVPN_SIMPLE_EXCEPTION(ipv6_not_implemented);
    OPENVPN_EXCEPTION(ipv6_parse_exception);

    class Addr // NOTE: must be union-legal, so default constructor does not initialize
    {
      friend class IP::Addr;

    public:
      enum { SIZE=128 };

      static Addr from_string(const std::string& ipstr, const char *title = NULL)
      {
	boost::system::error_code ec;
	boost::asio::ip::address_v6 a = boost::asio::ip::address_v6::from_string(ipstr, ec);
	if (ec)
	  {
	    if (!title)
	      title = "";
	    OPENVPN_THROW(ipv6_parse_exception, "error parsing " << title << " IPv6 address '" << ipstr << "' : " << ec.message());
	  }
	return from_asio(a);
      }

      std::string to_string() const
      {
	const boost::asio::ip::address_v6 a = to_asio();
	boost::system::error_code ec;
	std::string ret = a.to_string(ec);
	if (ec)
	  throw ipv6_render_exception();
	return ret;
      }

      static Addr from_asio(const boost::asio::ip::address_v6& asio_addr)
      {
	Addr ret;
	boost::asio::ip::address_v6::bytes_type bytes = asio_addr.to_bytes();
	ret.scope_id_ = asio_addr.scope_id();
	std::memcpy(ret.u.bytes, bytes.data(), 16);
	return ret;
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
	throw ipv6_not_implemented(); // fixme for ipv6
      }

      boost::asio::ip::address_v6 to_asio() const
      {
	boost::asio::ip::address_v6::bytes_type bytes;
	std::memcpy(bytes.data(), u.bytes, 16);
	return boost::asio::ip::address_v6(bytes, scope_id_);
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

      // return the network that contains the current address
      Addr network_addr(const unsigned int prefix_len) const
      {
	throw ipv6_not_implemented(); // fixme for ipv6
      }

      bool operator==(const Addr& other) const
      {
	return u.u64[0] == other.u.u64[0] && u.u64[1] == other.u.u64[1];
      }

      bool unspecified() const
      {
	return u.u64[0] == 0 && u.u64[1] == 0;
      }

      unsigned int prefix_len() const
      {
	throw ipv6_not_implemented(); // fixme for ipv6
      }

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
	for (int i = 15; i >= 0; --i)
	  {
	    if (++u.bytes[i])
	      break;
	  }
	return *this;
      }

    private:
      friend std::size_t hash_value(const Addr&);

      union {
	boost::uint64_t u64[2];
	boost::uint32_t u32[4];
	unsigned char bytes[16];
      } u;

      unsigned int scope_id_;
    };

    OPENVPN_OSTREAM(Addr, to_string)

    inline std::size_t hash_value(const Addr& addr)
    {
      std::size_t seed = 0;
      boost::hash_combine(seed, addr.u.u32[0]);
      boost::hash_combine(seed, addr.u.u32[1]);
      boost::hash_combine(seed, addr.u.u32[2]);
      boost::hash_combine(seed, addr.u.u32[3]);
      return seed;
    }
  }
} // namespace openvpn

#endif // OPENVPN_ADDR_IPV6_H
