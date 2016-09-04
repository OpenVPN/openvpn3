//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Create an Asio time_traits class to allow Asio to natively handle
// our Time and Time::Duration classes.

#ifndef OPENVPN_TIME_ASIOTIMER_H
#define OPENVPN_TIME_ASIOTIMER_H

#include <chrono>

#include <asio.hpp>
#include <asio/basic_waitable_timer.hpp>

#include <openvpn/common/olong.hpp>
#include <openvpn/time/time.hpp>

namespace openvpn {
  struct AsioClock
  {
    typedef olong rep;
    typedef std::ratio<1, 1024> period; // time resolution of openvpn::Time
    typedef std::chrono::duration<rep, period> duration;
    typedef std::chrono::time_point<AsioClock> time_point;

    static constexpr bool is_steady()
    {
      return false;
    }

    static time_point now()
    {
      return to_time_point(Time::now());
    }

    static time_point to_time_point(const Time& t)
    {
      return time_point(duration(t.raw()));
    }
  };

  class AsioTimer : public asio::basic_waitable_timer<AsioClock>
  {
  public:
    AsioTimer(asio::io_context& io_context)
      : asio::basic_waitable_timer<AsioClock>(io_context)
    {
    }

    std::size_t expires_at(const Time& t)
    {
      return asio::basic_waitable_timer<AsioClock>::expires_at(AsioClock::to_time_point(t));
    }    
  };
}

#endif
