#include <time.h>
#include <iostream>
#include <boost/asio/time_traits.hpp>

int main()
{
  typedef boost::asio::time_traits<boost::posix_time::ptime> time_traits;
  for (int i = 0; i < 1; ++i)
    {
      //time_t t = time(NULL);
      const time_traits::time_type t = time_traits::now();
      std::cout << long(t) << std::endl;
    }
  return 0;
}
