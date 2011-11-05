#ifndef OPENVPN_COMMON_TIME_H
#define OPENVPN_COMMON_TIME_H

#include <sys/time.h>

#include <openvpn/common/exception.hpp>

namespace openvpn {
  OPENVPN_SIMPLE_EXCEPTION(get_time_error);

  template <typename T>
  class TimeType
  {
  public:
    enum { prec=1024 };
    typedef ::time_t base_type;
    typedef T type;

    class Duration
    {
      friend class TimeType;

    public:
      static Duration seconds(const T v) { return Duration(v * prec); }
      static Duration binary_ms(const T v) { return Duration(v); }

      Duration() : duration_(T(0)) {}

      operator bool() const { return duration_ != 0; }
      bool operator!() const { return duration_ == 0; }

      Duration operator+(const Duration& d) const { return Duration(duration_ + d.duration_); }
      Duration operator-(const Duration& d) const { return Duration(duration_ - d.duration_); }

      Duration& operator+=(const Duration& d) { duration_ += d.duration_; return *this; }
      Duration& operator-=(const Duration& d) { duration_ -= d.duration_; return *this; }

      Duration operator*(const T mul) { return Duration(duration_ * mul); }
      Duration& operator*=(const T mul) { duration_ *= mul; return *this; }

      T to_seconds() const { return duration_ / prec; }
      T to_binary_ms() const { return duration_; }
      T to_microseconds() const { return duration_ * 1000000 / prec; }

#     define OPENVPN_DURATION_REL(OP) bool operator OP(const Duration& d) const { return duration_ OP d.duration_; }
      OPENVPN_DURATION_REL(==)
      OPENVPN_DURATION_REL(!=)
      OPENVPN_DURATION_REL(>)
      OPENVPN_DURATION_REL(<)
      OPENVPN_DURATION_REL(>=)
      OPENVPN_DURATION_REL(<=)
#     undef OPENVPN_DURATION_REL

    private:
      explicit Duration(const T duration) : duration_(duration) {}

      T duration_;
    };

    TimeType() : time_(T(0)) {}

    operator bool() const { return time_ != 0; }
    bool operator!() const { return time_ == 0; }

    base_type seconds_since_epoch() const { return base_ + time_ / prec; }
    T fractional_binary_ms() const { return time_ % prec; }

    static TimeType now()
    {
      ::timeval tv;
      if (::gettimeofday(&tv, NULL) != 0)
	throw get_time_error();
      return TimeType((tv.tv_sec - base_) * prec + tv.tv_usec * prec / 1000000);
    }

    static void reset_base() { base_ = ::time(0); }

    TimeType operator+(const Duration& d) const { return TimeType(time_ + d.duration_); }
    Duration operator-(const TimeType& t) const { return Duration(time_ - t.time_); }

#   define OPENVPN_TIME_REL(OP) bool operator OP(const TimeType& t) const { return time_ OP t.time_; }
    OPENVPN_TIME_REL(==)
    OPENVPN_TIME_REL(!=)
    OPENVPN_TIME_REL(>)
    OPENVPN_TIME_REL(<)
    OPENVPN_TIME_REL(>=)
    OPENVPN_TIME_REL(<=)
#   undef OPENVPN_TIME_REL

  private:
    explicit TimeType(const T time) : time_(time) {}

    static base_type base_;
    T time_;
  };

  template <typename T> typename TimeType<T>::base_type TimeType<T>::base_;

  typedef TimeType<unsigned int> Time;

} // namespace openvpn

#endif // OPENVPN_COMMON_TIME_H
