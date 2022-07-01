#include "test_common.h"
#include <iostream>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/ip/ping6.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/pool.hpp>

using namespace openvpn;

static const uint8_t icmp6_packet[] = {
  0x60, 0x06, 0x22, 0xe5, 0x00, 0x40, 0x3a, 0x28, 0x26, 0x01, 0x02, 0x81, 0x84, 0x80, 0x14, 0xe0,
  0xbc, 0xc1, 0x91, 0x20, 0xfc, 0xa3, 0x0e, 0x22, 0x26, 0x00, 0x1f, 0x18, 0x47, 0x2b, 0x89, 0x05,
  0x2a, 0xc4, 0x3b, 0xf3, 0xd5, 0x77, 0x29, 0x42, 0x80, 0x00, 0x99, 0x99, 0x3f, 0xd4, 0x00, 0x0e,
  0x43, 0xd4, 0xc3, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x3d, 0xc2, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

static bool verbose = false;

TEST(IPAddr, icmp6csum)
{
  const ICMPv6* icmp = (const ICMPv6*) icmp6_packet;
  const size_t len = sizeof(icmp6_packet);

  if (verbose)
    {
      std::cout << "From : " << IPv6::Addr::from_in6_addr(&icmp->head.saddr).to_string() << std::endl;
      std::cout << "To   : " << IPv6::Addr::from_in6_addr(&icmp->head.daddr).to_string() << std::endl;
    }
  const std::uint16_t csum = Ping6::csum_icmp(icmp, len);
  if (verbose)
    {
      std::cout << "Checksum: " << csum << std::endl;
    }
  ASSERT_TRUE (csum == 0) << "checksum=" << csum << " but should be zero";
}

TEST(IPAddr, pool)
{
  IP::Pool pool;
  pool.add_range(IP::Range(IP::Addr::from_string("1.2.3.4"), 16));
  pool.add_range(IP::Range(IP::Addr::from_string("Fe80::23a1:b152"), 4));
  pool.add_addr(IP::Addr::from_string("10.10.1.1"));
  ASSERT_TRUE(pool.acquire_specific_addr(IP::Addr::from_string("1.2.3.10")));

  std::stringstream s;
  for (int i = 0;; ++i)
    {
      IP::Addr addr;
      if (i == 7)
	{
	  pool.release_addr(IP::Addr::from_string("1.2.3.7"));
	}
      else if (i == 11)
	{
	  pool.release_addr(IP::Addr::from_string("1.2.3.3"));
	  pool.release_addr(IP::Addr::from_string("1.2.3.4"));
	  pool.release_addr(IP::Addr::from_string("1.2.3.5"));
	}
      else
	{
	  if (pool.acquire_addr(addr))
	    {
	      s << addr << " (" << pool.n_in_use() << ")" << std::endl;
	    }
	  else
	    break;
	}
    }
  ASSERT_EQ("1.2.3.4 (1)\n"
	    "1.2.3.5 (2)\n"
	    "1.2.3.6 (3)\n"
	    "1.2.3.7 (4)\n"
	    "1.2.3.8 (5)\n"
	    "1.2.3.9 (6)\n"
	    "1.2.3.11 (8)\n"
	    "1.2.3.12 (8)\n"
	    "1.2.3.13 (9)\n"
	    "1.2.3.14 (10)\n"
	    "1.2.3.15 (9)\n"
	    "1.2.3.16 (10)\n"
	    "1.2.3.17 (11)\n"
	    "1.2.3.18 (12)\n"
	    "1.2.3.19 (13)\n"
	    "fe80::23a1:b152 (14)\n"
	    "fe80::23a1:b153 (15)\n"
	    "fe80::23a1:b154 (16)\n"
	    "fe80::23a1:b155 (17)\n"
	    "10.10.1.1 (18)\n"
	    "1.2.3.7 (19)\n"
	    "1.2.3.4 (20)\n"
	    "1.2.3.5 (21)\n", s.str());
}