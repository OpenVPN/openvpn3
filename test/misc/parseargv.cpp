#include <iostream>

#include <openvpn/log/logsimple.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/options.hpp>

using namespace openvpn;

int main(int argc, char* argv[])
{
  try {
    const OptionList opt = OptionList::parse_from_argv_static(string::from_argv(argc, argv, true));
    std::cout << opt.render(Option::RENDER_NUMBER|Option::RENDER_BRACKET);
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
