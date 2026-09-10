#include "test_common.hpp"

#include <openvpn/time/time.hpp>
#include <openvpn/random/mtrandapi.hpp>

#include <openvpn/time/skew.hpp>
#include <openvpn/common/format.hpp>

#include <cmath>
#include <cstdint>

using namespace openvpn;
using namespace openvpn;

//! Draws per Time.Timeskew run
constexpr int SAMPLES = 10000;

//! Standard errors of slack allowed around each expected mean
constexpr double STD_ERRORS = 5.0;

//! Arbitrary fixed PRNG seed, so that an unlucky stream cannot fail a statistical check
constexpr std::uint64_t PRNG_SEED = 20250910;

int my_abs(const int value)
{
    if (value >= 0)
        return value;
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

    void check_mean_range(const std::string &title, const int low, const int hi) const
    {
        const int m = mean();
        ASSERT_TRUE(m > low && m < hi) << title << ' ' << to_string() << " outside of range=(" << low << ',' << hi << ')';
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

void test_skew(const Time::Duration &dur,
               const unsigned int skew_factor,
               MeanDev &md,
               const bool verbose,
               RandomAPI &prng)
{
    const Time::Duration after = TimeSkew::skew(dur, skew_factor, prng);
    md.mean.add(static_cast<int>(after.to_binary_ms()));
    md.dev.add(my_abs(int(dur.to_binary_ms()) - int(after.to_binary_ms())));
    if (verbose)
        OPENVPN_LOG("BEFORE=" << dur.to_binary_ms() << " AFTER=" << after.to_binary_ms());
}

TEST(Time, Timeskew)
{
    // Seeded, because the checks below are statistical and a failure has to reproduce.
    MTRand::Ptr prng(new MTRand(PRNG_SEED));
    const Time::Duration dur = Time::Duration::seconds(10);

    MeanDev md;
    for (int i = 0; i < SAMPLES; ++i)
    {
        test_skew(dur, TimeSkew::PCT_25, md, false, *prng);
    }
    // OPENVPN_LOG(md.to_string());

    // skew() adds a flux uniform over [-bms/2, bms/2) with bms = dur >> factor, so
    // over SAMPLES draws the mean converges on dur and the mean deviation on bms/4,
    // with standard errors of bms/sqrt(12*SAMPLES) and bms/sqrt(48*SAMPLES).
    const int dur_ms = static_cast<int>(dur.to_binary_ms());
    const int bms = dur_ms >> TimeSkew::PCT_25;
    const int mean_tol = static_cast<int>(STD_ERRORS * bms / std::sqrt(12.0 * SAMPLES));
    const int dev_tol = static_cast<int>(STD_ERRORS * bms / std::sqrt(48.0 * SAMPLES));

    md.mean.check_mean_range("mean", dur_ms - mean_tol, dur_ms + mean_tol);
    md.dev.check_mean_range("dev", bms / 4 - dev_tol, bms / 4 + dev_tol);
}

TEST(Time, Test1)
{
    Time::reset_base();

    const Time until = Time::now() + Time::Duration::seconds(1);

    Time::base_type last_sec = 0;
    Time::type last_frac = 0;

    while (true)
    {
        const Time t = Time::now();
        if (t >= until)
            break;
        const Time::base_type sec = t.seconds_since_epoch();
        const Time::type frac = t.fractional_binary_ms();
        if (sec != last_sec || frac != last_frac)
        {
            // std::cout << sec << ' ' << frac << "\n";
            last_sec = sec;
            last_frac = frac;
        }
    }
}

static void sub(const Time &t1, const Time &t2, bool large)
{
    const Time::Duration d = t1 - t2;
    // std::cout << "T-T " << t1.raw() << " - " << t2.raw() << " = " << d.raw() << "\n";
    if (large)
        ASSERT_GE(d.raw(), 100000U);
    else
        ASSERT_EQ(d.raw(), 0U);
}

static void sub(const Time::Duration &d1, const Time::Duration &d2)
{
    const Time::Duration d = d1 - d2;
    // std::cout << "D-D " << d1.raw() << " - " << d2.raw() << " = " << d.raw() << "\n";
    Time::Duration x = d1;
    x -= d2;
    ASSERT_EQ(x, d) << "D-D INCONSISTENCY DETECTED";
}

static void add(const Time &t1, const Time::Duration &d1)
{
    const Time t = t1 + d1;
    // std::cout << "T+D " << t1.raw() << " + " << d1.raw() << " = " << t.raw() << "\n";
    Time x = t1;
    x += d1;
    ASSERT_EQ(x, t) << "T+D INCONSISTENCY DETECTED";
}

static void add(const Time::Duration &d1, const Time::Duration &d2)
{
    const Time::Duration d = d1 + d2;
    // std::cout << "D+D " << d1.raw() << " + " << d2.raw() << " = " << d.raw() << "\n";
    Time::Duration x = d1;
    x += d2;
    ASSERT_EQ(x, d) << "D+D INCONSISTENCY DETECTED";
}

TEST(Time, Timeaddsub)
{
    {
        const Time now = Time::now();
        const Time inf = Time::infinite();
        sub(now, now, false);
        sub(inf, now, true);
        sub(now, inf, false);
        sub(inf, inf, false);
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
