#include "test_common.h"

#include <iostream>
#include <cstdint>

#include <openvpn/common/format.hpp>
#include <openvpn/random/mtrandapi.hpp>

#include <openvpn/time/skew.hpp>

using namespace openvpn;

int my_abs(const int value)
{
  if (value >= 0)
    return value;
  else
    return -value;
}

class Mean
{
public:
  void add(const int value)
  {
    sum_ += value;
    ++count_;
  }

  int mean() const
  {
    return sum_ / count_;
  }

  void check_mean_range(const std::string& title, const int low, const int hi) const
  {
    const int m = mean();
    ASSERT_TRUE (m > low && m < hi) << title << ' ' << to_string() << " outside of range=[" << low << ',' << hi << ']';
  }

  int count() const
  {
    return count_;
  }

  std::string to_string() const
  {
    return printfmt("[mean=%s count=%s]", mean(), count());
  }

private:
  int count_ = 0;
  int sum_ = 0;
};

struct MeanDev
{
  Mean mean;
  Mean dev;

  std::string to_string() const
  {
    return mean.to_string() + " dev=" + dev.to_string();
  }
};

void test_skew(const Time::Duration& dur,
	       const unsigned int skew_factor,
	       MeanDev& md,
	       const bool verbose,
	       RandomAPI& prng)
{
  const Time::Duration after = TimeSkew::skew(dur, skew_factor, prng);
  md.mean.add(after.to_binary_ms());
  md.dev.add(my_abs(int(dur.to_binary_ms()) - int(after.to_binary_ms())));
  if (verbose)
    OPENVPN_LOG("BEFORE=" << dur.to_binary_ms() << " AFTER=" << after.to_binary_ms());
}

TEST(misc, timeskew)
{
  MTRand::Ptr prng(new MTRand());
  MeanDev md;
  for (int i = 0; i < 10000; ++i)
    {
      test_skew(Time::Duration::seconds(10), TimeSkew::PCT_25, md, false, *prng);
    }
  //OPENVPN_LOG(md.to_string());
  md.mean.check_mean_range("mean", 10200, 10300);
  md.dev.check_mean_range("dev", 1250, 1300);
}