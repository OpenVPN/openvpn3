#include <iostream>
#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/addr/ip.hpp>

using namespace openvpn;

OPENVPN_SIMPLE_EXCEPTION(ipv4_bad_prefix_len);
OPENVPN_SIMPLE_EXCEPTION(ipv4_bad_netmask);

inline IPv4::Addr::base_type prefix_len_to_netmask_unchecked(const unsigned int prefix_len)
{
  return ~((1 << (32 - prefix_len)) - 1);
}

inline IPv4::Addr::base_type prefix_len_to_netmask(const unsigned int prefix_len)
{
  if (prefix_len >= 1 && prefix_len <= 32)
    return prefix_len_to_netmask_unchecked(prefix_len);
  else
    throw ipv4_bad_prefix_len();
}

inline int prefix_len(const IPv4::Addr::base_type mask)
{
  if (mask != ~0)
    {
      unsigned int high = 32;
      unsigned int low = 1;
      for (unsigned int i = 0; i < 5; ++i)
	{
	  const unsigned int mid = (high + low) / 2;
	  const IPv4::Addr::base_type test = prefix_len_to_netmask_unchecked(mid);
	  if (mask == test)
	    return mid;
	  else if (mask > test)
	    low = mid;
	  else
	    high = mid;
	}
      return -1;
    }
  else
    return 32;
}

void test32() // test using methods above
{
  for (unsigned int i = 1; i <= 32; ++i)
    {
      const IPv4::Addr::base_type mask = prefix_len_to_netmask(i);
      IPv4::Addr a = IPv4::Addr::from_uint32(mask);
      const int pl = prefix_len(mask);
      if (pl != i)
	std::cout << "ERROR" << std::endl;
      std::cout << i << ' ' << pl << ' ' << a << std::endl;
    }
}

void testaddr() // test using IPv4::Addr::prefix_len
{
  for (unsigned int i = 0; i <= 32; ++i)
    {
      IPv4::Addr mask = IPv4::Addr::netmask_from_prefix_len(i);
      const unsigned int pl = mask.prefix_len();
      if (pl != i)
	std::cout << "ERROR" << std::endl;
      std::cout << i << ' ' << pl << ' ' << mask << std::endl;
    }
}

void testbig() // exhaustive test of all 2^32 possible netmask values
{
  unsigned int mask = 0;
  while (true)
    {
      const int pl = prefix_len(mask);
      if (pl != -1)
	std::cout << pl << ' ' << IPv4::Addr::from_uint32(mask) << std::endl;
      if (++mask == 0)
	break;
    }
}

int main()
{
  try {
    //test32();
    testaddr();
    //testbig();
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
