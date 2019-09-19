// TEST : {"cmd": "./go cleanup"}

#include <iostream>
#include <memory>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/common/cleanup.hpp>

using namespace openvpn;

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    bool ran_cleanup = false;
    {
      auto c = Cleanup([&]() {
	  ran_cleanup = true;
	});
      static_assert(std::is_nothrow_move_constructible<decltype(c)>::value,
		    "Cleanup should be noexcept MoveConstructible");
    }
    if (!ran_cleanup)
      throw Exception("cleanup didn't run as expected");
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
