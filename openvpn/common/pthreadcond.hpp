//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_COMMON_PTHREADCOND_H
#define OPENVPN_COMMON_PTHREADCOND_H

#include <openvpn/common/abort.hpp>
#include <openvpn/common/format.hpp>

#include <pthread.h>
#include <time.h>
#include <errno.h>

namespace openvpn {

  class PThreadCond
  {
  public:
    PThreadCond()
      : signaled(false),
	signal_counter(0),
	cond(PTHREAD_COND_INITIALIZER),
	mutex(PTHREAD_MUTEX_INITIALIZER)
    {
    }

    void wait()
    {
      lock();
      const unsigned int signal_value = signal_counter;
      while (!signaled && signal_value == signal_counter)
	cond_wait();
      unlock();
    }

    // returns true if timeout
    bool wait(const unsigned int seconds)
    {
      bool ret = false;
      lock();
      const unsigned int signal_value = signal_counter;
      while (!signaled && signal_value == signal_counter && !ret)
	ret = cond_wait(seconds);
      unlock();
      return ret;
    }

    void signal()
    {
      lock();
      signaled = true;
      ++signal_counter;
      bcast();
      unlock();
    }

    void reset()
    {
      lock();
      signaled = false;
      unlock();
    }

  private:
    void lock()
    {
      const int status = pthread_mutex_lock(&mutex);
      if (status)
	error("pthread_mutex_lock", status);
    }

    void unlock()
    {
      const int status = pthread_mutex_unlock(&mutex);
      if (status)
	error("pthread_mutex_unlock", status);
    }

    void bcast()
    {
      const int status = pthread_cond_broadcast(&cond);
      if (status)
	error("pthread_cond_broadcast", status);
    }

    void cond_wait()
    {
      const int status = pthread_cond_wait(&cond, &mutex);
      if (status)
	error("pthread_cond_wait", status);
    }

    bool cond_wait(const unsigned int seconds)
    {
      struct timespec ts;
      if (clock_gettime(CLOCK_REALTIME, &ts))
	error("clock_gettime", errno);
      ts.tv_sec += seconds;
      const int status = pthread_cond_timedwait(&cond, &mutex, &ts);
      if (status == ETIMEDOUT)
	return true;
      if (status)
	error("pthread_cond_timedwait", status);
      return false;
    }

    void error(const char *funcname, const int status)
    {
      OPENVPN_LOG("PThreadCond: " << funcname << " returned " << status);
      std::abort();
    }

    bool signaled;
    unsigned int signal_counter;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
  };
}

#endif
