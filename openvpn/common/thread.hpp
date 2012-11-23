//
//  thread.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
