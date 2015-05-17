#include <iostream>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/time/time.hpp>

using namespace openvpn;

int main()
{
  try {
    Time::reset_base();

    const Time until = Time::now() + Time::Duration::seconds(5);

    Time::base_type last_sec = 0;
    Time::type last_frac = 0;

    while (true)
      {
	const Time t = Time::now();
	if (t >= until)
	  break;
	const Time::base_type sec = t.seconds_since_epoch();
	const Time::type frac = t.fractional_binary_ms();
	if (sec != last_sec || frac != last_frac)
	  {
	    std::cout << sec << ' ' << frac << std::endl;
	    last_sec = sec;
	    last_frac = frac;
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
