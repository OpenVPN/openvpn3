#ifndef OPENVPN_COMMON_THREAD_H
#define OPENVPN_COMMON_THREAD_H

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

#endif // OPENVPN_COMMON_THREAD_H
