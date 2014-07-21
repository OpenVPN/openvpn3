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

// Basic definitions and includes for multi-threaded code.

#ifndef OPENVPN_COMMON_THREAD_H
#define OPENVPN_COMMON_THREAD_H

#include <boost/asio.hpp>

#if defined(BOOST_HAS_THREADS) && !defined(BOOST_ASIO_DISABLE_THREADS)
#define OPENVPN_MULTITHREAD 1
#else
#define OPENVPN_MULTITHREAD 0
#endif

#if OPENVPN_MULTITHREAD
#include <boost/thread/thread.hpp>
#include <boost/asio/detail/tss_ptr.hpp>
#include <boost/asio/detail/mutex.hpp>
#endif

namespace openvpn {
  typedef boost::asio::detail::mutex Mutex;
}

#endif // OPENVPN_COMMON_THREAD_H
