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

template <typename LIST>
void test_split(const LIST& rtlist)
{
  OPENVPN_LOG("TEST SPLIT");
  typedef typename LIST::value_type RT;
  for (const auto &r : rtlist)
    {
      RT r1, r2;
      if (r.is_canonical() && r.split(r1, r2))
	OPENVPN_LOG(r << ' ' << r1 << ' ' << r2);
    }
}

void test_list4()
{
  OPENVPN_LOG("===== ROUTE4 LIST =====");
  IP::Route4List routes;
  routes.emplace_back("1.2.3.4/24");
  routes.emplace_back("1.2.3.0/24");
  routes.emplace_back("1.2.3.2/24");
  routes.emplace_back("1.2.3.1/24");
  routes.emplace_back("128.0.0.0/1");
  OPENVPN_LOG_NTNL(routes.to_string());
  if (routes.contains(IPv4::Addr::from_string("100.1.2.3")))
    throw Exception("unexpected contains #1");
  if (!routes.contains(IPv4::Addr::from_string("200.1.2.3")))
    throw Exception("unexpected contains #2");
  test_split(routes);
}

void test_list6()
{
  OPENVPN_LOG("===== ROUTE6 LIST =====");
  IP::Route6List routes;
  routes.emplace_back("1:2:3:4:5:6:dead:beef/64");
  routes.emplace_back("cafe:babe::/64");
  OPENVPN_LOG_NTNL(routes.to_string());
  if (routes.contains(IPv6::Addr::from_string("1111:2222:3333:4444:5555:6666:7777:8888")))
    throw Exception("unexpected contains #1");
  if (!routes.contains(IPv6::Addr::from_string("cafe:babe:0:0:1111:2222:3333:4444")))
    throw Exception("unexpected contains #2");
  test_split(routes);
}

void test_list()
{
  OPENVPN_LOG("===== ROUTE LIST =====");
  IP::RouteList routes;
  routes.emplace_back("1.2.3.4/24");
  routes.emplace_back("1.2.3.0/24");
  routes.emplace_back("1.2.3.2/24");
  routes.emplace_back("1.2.3.1/24");
  routes.emplace_back("128.0.0.0/1");
  routes.emplace_back("1:2:3:4:5:6:dead:beef/64");
  routes.emplace_back("cafe:babe::/64");
  OPENVPN_LOG_NTNL(routes.to_string());
  if (routes.contains(IP::Addr::from_string("100.1.2.3")))
    throw Exception("unexpected contains #1");
  if (!routes.contains(IP::Addr::from_string("200.1.2.3")))
    throw Exception("unexpected contains #2");
  if (routes.contains(IP::Addr::from_string("1111:2222:3333:4444:5555:6666:7777:8888")))
    throw Exception("unexpected contains #3");
  if (!routes.contains(IP::Addr::from_string("cafe:babe:0:0:1111:2222:3333:4444")))
    throw Exception("unexpected contains #4");
  test_split(routes);
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

    test_list4();
    test_list6();
    test_list();
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
