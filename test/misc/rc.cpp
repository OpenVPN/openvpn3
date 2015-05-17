#include <iostream>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/common/rc.hpp>

using namespace openvpn;

class Test : public RC<thread_safe_refcount>
{
public:
  typedef boost::intrusive_ptr<Test> Ptr;

  Test()
  {
    OPENVPN_LOG("Test()");
  }

  ~Test()
  {
    OPENVPN_LOG("~Test()");
  }
};

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    Test::Ptr t1 = new Test();
    Test::Ptr t2(t1);
    Test::Ptr t3(t2);
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
