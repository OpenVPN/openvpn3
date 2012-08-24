//
//  coarsetime.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TIME_COARSETIME_H
#define OPENVPN_TIME_COARSETIME_H

#include <openvpn/time/time.hpp>

namespace openvpn {

class CoarseTime
{
public:
  CoarseTime() {}

  CoarseTime(const Time::Duration& pre, const Time::Duration& post)
    : pre_(pre), post_(post) {}

  void init(const Time::Duration& pre, const Time::Duration& post)
  {
    pre_ = pre;
    post_ = post;
  }

  void reset(const Time& t) { time_ = t; }
  void reset() { time_.reset(); }

  bool similar(const Time& t) const
  {
    if (time_.defined())
      {
	if (t >= time_)
	  return (t - time_) <= post_;
	else
	  return (time_ - t) <= pre_;
      }
    else
      return false;
  }

private:
  Time time_;
  Time::Duration pre_;
  Time::Duration post_;
};

} // namespace openvpn

#endif // OPENVPN_TIME_COARSETIME_H
