//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

// Create an Asio time_traits class to allow Asio to natively handle
// our Time and Time::Duration classes.

#pragma once

#include <chrono>
#include <memory>

#include <openvpn/io/io.hpp> // was: #include <asio/basic_waitable_timer.hpp>

#include <openvpn/common/olong.hpp>
#include <openvpn/time/time.hpp>

namespace openvpn {
struct AsioClock
{
    typedef olong rep;
    typedef std::ratio<1, 1024> period; // time resolution of openvpn::Time, note 1024 instead of the usual 1000
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

    static time_point to_time_point(const Time &t)
    {
        return time_point(duration(t.raw()));
    }

    static duration to_duration(const Time::Duration &d)
    {
        return duration(d.raw());
    }
};

class AsioTimer : public openvpn_io::basic_waitable_timer<AsioClock>
{
  public:
    typedef std::unique_ptr<AsioTimer> UPtr;

    AsioTimer(openvpn_io::io_context &io_context)
        : openvpn_io::basic_waitable_timer<AsioClock>(io_context)
    {
    }

    std::size_t expires_at(const Time &t)
    {
        return openvpn_io::basic_waitable_timer<AsioClock>::expires_at(AsioClock::to_time_point(t));
    }

    std::size_t expires_after(const Time::Duration &d)
    {
        return openvpn_io::basic_waitable_timer<AsioClock>::expires_after(AsioClock::to_duration(d));
    }
};
} // namespace openvpn
