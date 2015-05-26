#include <iostream>
#include <string>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/common/rc.hpp>

using namespace openvpn;

class Test : public RCWeak<thread_safe_refcount>
{
public:
  typedef RCPtr<Test> Ptr;
  typedef RCWeakPtr<Test> WPtr;

  Test()
    : name("Test")
  {
    OPENVPN_LOG(name << "()");
  }

  ~Test()
  {
    OPENVPN_LOG("~" << name << "()");
  }

  void go(const char *title)
  {
    OPENVPN_LOG(title << ": " << name);    
  }

  std::string name;
};

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    {
      OPENVPN_LOG("TEST1");
      Test::Ptr t1 = new Test();
      Test::Ptr t2(t1);
      Test::Ptr t3(t2);
    }
    {
      OPENVPN_LOG("TEST2");

      Test::WPtr w1z;
      Test::WPtr w2z;

      {
	Test::Ptr t1 = new Test();
	Test::WPtr w1 = t1;
	RCWeakPtr<Test::WPtr::element_type> w2 = t1.get();
	w1z.reset(t1);
	w2z.reset(t1.get());

	Test::Ptr t1a = w1.lock();
	Test::Ptr t2a = w2.lock();

	t1a->go("t1a");
	t2a->go("t2a");

	t1a = w1z.lock();
	t2a = w2z.lock();

	t1a->go("t1b");
	t2a->go("t2b");

	Test::WPtr z;
	z.swap(w1);
	Test::Ptr tz = z.lock();
	tz->go("tz");

	tz = w1.lock();
	if (tz)
	  OPENVPN_LOG("BUG ALERT #1");

	z.reset();
	tz = z.lock();
	if (tz)
	  OPENVPN_LOG("BUG ALERT #2");

	OPENVPN_LOG("w1z=" << w1z.use_count() << " w2z=" << w2z.use_count());
      }

      Test::Ptr x = w1z.lock();
      Test::Ptr y = w2z.lock();
      if (x || y || !w1z.expired() || !w2z.expired())
	OPENVPN_LOG("BUG ALERT #3");
      else
	OPENVPN_LOG("OK!");
      w1z = w2z;
    }
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
