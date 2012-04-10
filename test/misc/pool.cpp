#include <iostream>

#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/pool.hpp>

using namespace openvpn;

int main()
{
  try {
    typedef IP::Addr Addr;
    IP::Pool<Addr> pool;
    pool.add_range(IP::Range<Addr>(Addr::from_string("1.2.3.4"), 16));
    pool.add_range(IP::Range<Addr>(Addr::from_string("Fe80::23a1:b152"), 4));
    pool.add_addr(Addr::from_string("10.10.1.1"));
    std::cout << "LF " << pool.load_factor() << std::endl;
    const bool b = pool.acquire_specific_addr(Addr::from_string("1.2.3.10"));
    std::cout << "GET 10: " << b << std::endl;
    for (int i = 0; ; ++i)
      {
	Addr addr;
	if (i == 7)
	  {
	    std::cout << "REL 7" << std::endl;
	    pool.release_addr(Addr::from_string("1.2.3.7"));
	  }
	else if (i == 11)
	  {
	    std::cout << "REL 3,4,5" << std::endl;
	    pool.release_addr(Addr::from_string("1.2.3.3"));
	    pool.release_addr(Addr::from_string("1.2.3.4"));
	    pool.release_addr(Addr::from_string("1.2.3.5"));
	  }
	else
	  {
	    if (pool.acquire_addr(addr))
	      {
		std::cout << addr << " (" << pool.n_in_use() << ")" << std::endl;
	      }
	    else
	      break;
	  }
      }
   }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
