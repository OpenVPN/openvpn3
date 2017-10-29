#include <iostream>
#include <set>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/addr/route.hpp>

using namespace openvpn;

void test(const std::string& rstr)
{
  const IP::Route r(rstr);
  std::cout << rstr << " -> " << r << std::endl;
}

void test4(const std::string& rstr)
{
  const IP::Route4 r(rstr);
  std::cout << rstr << " -> " << r << std::endl;
}

void test6(const std::string& rstr)
{
  const IP::Route6 r(rstr);
  std::cout << rstr << " -> " << r << std::endl;
}

void test_set()
{
  OPENVPN_LOG("===== ROUTE SET =====");
    std::set<IP::Route> routes;
    routes.emplace("1.2.3.4/24");
    routes.emplace("1.2.3.0/24");
    routes.emplace("1.2.3.2/24");
    routes.emplace("1.2.3.1/24");
    routes.emplace("128.0.0.0/1");
    routes.emplace("1:2:3:4:5:6:dead:beef/64");
    routes.emplace("1:2:3:4:5:6:dead:bead/64");

    for (const auto &r : routes)
      OPENVPN_LOG(r.to_string());
}

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    test("1.2.3.4");
    test("192.168.4.0/24");
    test("fe80::6470:7dff:fea5:f360/64");

    test4("1.2.3.4");
    test4("192.168.4.0/24");
    test6("fe80::6470:7dff:fea5:f360/64");

    try {
      test("192.168.4.0/33");
    }
    catch (const std::exception& e)
      {
	OPENVPN_LOG("expected exception: " << e.what());
      }

    test_set();
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
