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

#include <openvpn/common/platform.hpp>
#include <openvpn/common/abort.hpp>
#include <openvpn/common/format.hpp>

#include <pthread.h>
#include <time.h>
#include <errno.h>

namespace openvpn {

  class PThreadCondBase
  {
  protected:
    PThreadCondBase()
      : cond(PTHREAD_COND_INITIALIZER),
	mutex(PTHREAD_MUTEX_INITIALIZER)
    {
    }

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
      if (my_clock_gettime(&ts))
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
      OPENVPN_LOG("PThreadCondBase: " << funcname << " returned " << status);
      std::abort();
    }

    pthread_cond_t cond;
    pthread_mutex_t mutex;

  private:
    static int my_clock_gettime(struct timespec* ts)
    {
#if defined(OPENVPN_PLATFORM_TYPE_APPLE)
      struct timeval now;
      const int rv = gettimeofday(&now, NULL);
      if (rv)
	return rv;
      ts->tv_sec  = now.tv_sec;
      ts->tv_nsec = now.tv_usec * 1000;
      return 0;
#elif defined(OPENVPN_PLATFORM_LINUX)
      return clock_gettime(CLOCK_REALTIME, ts);
#else
#error no implementation for my_clock_gettime()
#endif
    }
  };

  // A condition implementation not unlike Windows Events.
  class PThreadCond : public PThreadCondBase
  {
  public:
    PThreadCond()
      : signaled(false),
	signal_counter(0)
    {
    }

    // Wait for object to be signaled
    void wait()
    {
      lock();
      const unsigned int signal_value = signal_counter;
      while (!signaled && signal_value == signal_counter)
	cond_wait();
      unlock();
    }

    // Wait for object to be signaled,
    // but return true on timeout
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

    // Causes wait() to return for all threads blocking on it
    void signal()
    {
      lock();
      signaled = true;
      ++signal_counter;
      bcast();
      unlock();
    }

    // Resets the object for re-use
    void reset()
    {
      lock();
      signaled = false;
      unlock();
    }

  private:
    bool signaled;
    unsigned int signal_counter;
  };

  // Barrier class that is useful in cases where all threads
  // need to reach a known point before executing some action.
  // Note that this barrier implementation is
  // constructed using pthread conditions.  We don't actually
  // use the native pthread barrier API.
  class PThreadBarrier : public PThreadCondBase
  {
    enum State {
      UNSIGNALED=0,  // initial state
      SIGNALED,      // signal() was called
      ERROR_THROWN,  // error() was called
    };

  public:
    // status return from wait()
    enum Status {
      SUCCESS=0,  // successful
      CHOSEN_ONE, // successful and chosen (only one thread is chosen)
      TIMEOUT,    // timeout
      ERROR,      // at least one thread called error()
    };

    PThreadBarrier(const int initial_limit = -1)
      : state(UNSIGNALED),
	chosen(false),
	count(0),
	limit(initial_limit)
    {
    }

    // All callers will increment count and block until
    // count == limit.  CHOSEN_ONE will be returned to
    // the first caller to reach limit.  This caller can
    // then release all the other callers by calling
    // signal().
    int wait(const unsigned int seconds)
    {
      bool timeout = false;
      int ret;

      lock();
      const unsigned int c = ++count;
      while (state == UNSIGNALED
	     && (limit < 0 || c < limit)
	     && !timeout)
	timeout = cond_wait(seconds);
      if (timeout)
	ret = TIMEOUT;
      else if (state == ERROR_THROWN)
	ret = ERROR;
      else if (state == UNSIGNALED && !chosen)
	{
	  ret = CHOSEN_ONE;
	  chosen = true;
	}
      else
	ret = SUCCESS;
      unlock();
      return ret;
    }

    void set_limit(const int new_limit)
    {
      lock();
      limit = new_limit;
      bcast();
      unlock();
    }

    // Generally, only the CHOSEN_ONE calls signal() after its work
    // is complete, to allow the other threads to pass the barrier.
    void signal()
    {
      signal_(SIGNALED);
    }

    // Causes all threads waiting on wait() (and those which call wait()
    // in the future) to exit with ERROR status.
    void error()
    {
      signal_(ERROR_THROWN);
    }

  private:
    void signal_(const State newstate)
    {
      lock();
      if (state == UNSIGNALED)
	{
	  state = newstate;
	  bcast();
	}
      unlock();
    }

    State state;
    bool chosen;
    unsigned int count;
    int limit;
  };

}

#endif
