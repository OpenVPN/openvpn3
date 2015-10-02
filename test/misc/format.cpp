#include <iostream>
#include <type_traits>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/common/format.hpp>
#include <openvpn/common/ostream.hpp>

using namespace openvpn;

class MyObj
{
public:
  MyObj(int v)
    : value(v)
  {
  }

  std::string to_string() const
  {
    return std::to_string(value);
  }

private:
  int value;
};

OPENVPN_OSTREAM(MyObj, to_string);

void test()
{
  const MyObj seven(7);
  const std::string foo = "foo";
  const char *const bar = "bar";
  const double pi = 3.14159265;
  const int three = 3;
  const std::string weather = "partly cloudy";
  char *nc = const_cast<char *>("non const");

  std::cout << to_string(seven) << std::endl;
  std::cout << to_string(foo) << std::endl;
  std::cout << to_string(bar) << std::endl;
  std::cout << to_string(pi) << std::endl;
  std::cout << to_string(three) << std::endl;
  std::cout << to_string(true) << std::endl;
  std::cout << to_string(false) << std::endl;
  std::cout << prints("pi", "is", std::string("not"), 3, "nor is it", seven, ';', "it", "is", pi, "...") << std::endl;
  std::cout << printfmt("pi is %r %s nor is it %s ; it is %s... (and has %s%% less %s!)", "not", 3, seven, pi, 99, std::string("fat")) << std::endl;
  std::cout << printfmt("the year is %s and the weather is %R", 2015, weather) << std::endl;
  std::cout << printfmt("where am %s? is it still %s?", 'I', 2015) << std::endl;
  std::cout << printfmt("no, it's %s... bring out yer dedd%s", 1666) << std::endl;
  std::cout << printfmt("save 20%%!") << std::endl;
  std::cout << printfmt("no wait... save%s 99.9999%%!") << std::endl;
  std::cout << printfmt("extra argument is here", 1) << std::endl;
  std::cout << printfmt("is the question %s or %s?", true, false) << std::endl;
  std::cout << printfmt("more extra arguments are here", 1, 2, 3, 4) << std::endl;
  std::cout << printfmt("null string '%s'", static_cast<const char *>(nullptr)) << std::endl;
  std::cout << printfmt("nullptr '%s'", nullptr) << std::endl;
  std::cout << printfmt("%s=%s %s", foo, bar, nc) << std::endl;
  try {
    const std::string exstr = "bad foo";
    throw Exception(exstr);
  }
  catch (const std::exception& e)
    {
      std::cout << prints("EX1:", e.what()) << std::endl;
    }
  try {
    throw Exception(prints("this", "prog", "is", "done", 4, 'U'));
  }
  catch (const std::exception& e)
    {
      std::cout << prints("EX2:", e.what()) << std::endl;
    }
}

template<typename... Args>
inline std::string pfmt(const std::string& fmt, Args... args)
{
#if 1
  PrintFormatted<std::string> pf(fmt, 256);
#else
  PrintFormatted<std::ostringstream> pf(fmt, 256);
#endif
  pf.process(args...);
  return pf.str();
}

void perf()
{
  const MyObj seven(7);
  //const double pi = 3.14159265;
  long count = 0;
  const std::string weather = "partly cloudy";
  for (long i = 0; i < 1000000; ++i)
    {
      const std::string str = pfmt("the year is %s and the weather is %r", 2015, weather);
      //const std::string str = pfmt("this program is brought to you by the number %s", seven);
      //const std::string str = pfmt("foo %s", 69);
      //const std::string str = pfmt("foo");
      //const std::string str = pfmt("foo %s %s", 69, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
      //const std::string str = pfmt("pi is %s %s nor is it %s ; it is %s... (and has %s%% less %s!)", "not", 3, seven, pi, 99, std::string("fat"));
      count += str.length();
    }
  std::cout << count << std::endl;
}

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    test();
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
