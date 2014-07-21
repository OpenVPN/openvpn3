//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

#include <boost/asio.hpp>

#include <openvpn/time/time.hpp>

namespace boost {
  namespace asio {

    // asio time traits specialized for our Time type
    template <>
    struct time_traits<openvpn::Time>
    {
      typedef openvpn::Time time_type;
      typedef openvpn::Time::Duration duration_type;

      static time_type now()
      {
	return time_type::now();
      }

      static time_type add(const time_type& t, const duration_type& d)
      {
	return t + d;
      }

      static duration_type subtract(const time_type& t1, const time_type& t2)
      {
	return t1 - t2;
      }

      static bool less_than(const time_type& t1, const time_type& t2)
      {
	return t1 < t2;
      }

      /// Convert to POSIX duration type.
      static boost::posix_time::time_duration to_posix_duration(const duration_type& d)
      {
	if (d.is_infinite())
	  return boost::posix_time::seconds(86400*365);
	else
	  return boost::posix_time::milliseconds(d.to_milliseconds());
      }
    };

  } // namespace asio
} // namespace boost

namespace openvpn {
  typedef boost::asio::basic_deadline_timer<Time> AsioTimer;
}

#endif // OPENVPN_TIME_ASIOTIMER_H
