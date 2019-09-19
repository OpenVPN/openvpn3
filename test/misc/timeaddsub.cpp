// TEST : {"cmd": "./go timeaddsub"}

#include <iostream>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/time/time.hpp>

using namespace openvpn;

void sub(const Time& t1, const Time& t2)
{
  const Time::Duration d = t1 - t2;
  std::cout << "T-T " << t1.raw() << " - " << t2.raw() << " = " << d.raw() << std::endl;
}

void sub(const Time::Duration& d1, const Time::Duration& d2)
{
  const Time::Duration d = d1 - d2;
  std::cout << "D-D " << d1.raw() << " - " << d2.raw() << " = " << d.raw() << std::endl;
  Time::Duration x = d1;
  x -= d2;
  if (x != d)
    OPENVPN_THROW_EXCEPTION("D-D INCONSISTENCY DETECTED");
}

void add(const Time& t1, const Time::Duration& d1)
{
  const Time t = t1 + d1;
  std::cout << "T+D " << t1.raw() << " + " << d1.raw() << " = " << t.raw() << std::endl;
  Time x = t1;
  x += d1;
  if (x != t)
    OPENVPN_THROW_EXCEPTION("T+D INCONSISTENCY DETECTED");
}

void add(const Time::Duration& d1, const Time::Duration& d2)
{
  const Time::Duration d = d1 + d2;
  std::cout << "D+D " << d1.raw() << " + " << d2.raw() << " = " << d.raw() << std::endl;
  Time::Duration x = d1;
  x += d2;
  if (x != d)
    OPENVPN_THROW_EXCEPTION("D+D INCONSISTENCY DETECTED");
}

int main()
{
  try {
    {
      const Time now = Time::now();
      const Time inf = Time::infinite();
      sub(now, now);
      sub(inf, now);
      sub(now, inf);
      sub(inf, inf);
    }
    {
      const Time::Duration sec = Time::Duration::seconds(1);
      const Time::Duration inf = Time::Duration::infinite();
      sub(sec, sec);
      sub(inf, sec);
      sub(sec, inf);
      sub(inf, inf);
    }
    {
      const Time tf = Time::now();
      const Time ti = Time::infinite();
      const Time::Duration df = Time::Duration::seconds(1);
      const Time::Duration di = Time::Duration::infinite();
      add(tf, df);
      add(tf, di);
      add(ti, df);
      add(ti, di);
    }
    {
      const Time::Duration sec = Time::Duration::seconds(1);
      const Time::Duration inf = Time::Duration::infinite();
      add(sec, sec);
      add(inf, sec);
      add(sec, inf);
      add(inf, inf);
    }
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
