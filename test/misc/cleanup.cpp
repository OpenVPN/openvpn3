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
    std::unique_ptr<std::string> str(new std::string("Hello world!"));
    auto c = Cleanup([str=std::move(str)]() {
	OPENVPN_LOG("HIT IT: " << *str);
      });
    static_assert(std::is_nothrow_move_constructible<decltype(c)>::value,
		  "Cleanup should be noexcept MoveConstructible");

    OPENVPN_LOG("Starting...");
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
