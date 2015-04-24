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

#ifndef OPENVPN_COMMON_RUNCONTEXT_H
#define OPENVPN_COMMON_RUNCONTEXT_H

#include <type_traits> // for std::is_nothrow_move_constructible

#include <openvpn/common/exception.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/thread.hpp>
#include <openvpn/common/asiosignal.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/time/timestr.hpp>

namespace openvpn {

  struct ServerThreadBase : public RC<thread_safe_refcount>
  {
    typedef boost::intrusive_ptr<ServerThreadBase> Ptr;

    virtual void thread_safe_stop() = 0;
  };

  template <typename ServerThread, typename Stats>
  class RunContext : public LogBase
  {
    struct Thread
    {
      Thread() : thread(NULL) {}

      Thread(Thread&& ref) noexcept
	: thread(ref.thread),
	  serv(std::move(ref.serv))
      {
	static_assert(std::is_nothrow_move_constructible<Thread>::value, "class RunContext::Thread not noexcept move constructable");
	ref.thread = NULL;
      }

      Thread(ThreadType* thread_arg) : thread(thread_arg) {}

      ~Thread() { delete thread; }

      Thread(const Thread&) = delete;
      Thread& operator=(const Thread&) = delete;

      ThreadType* thread;
      typename ServerThread::Ptr serv;
    };

  public:
    typedef boost::intrusive_ptr<RunContext> Ptr;

    class ThreadContext
    {
    public:
      ThreadContext(RunContext& ctx_arg)
	: ctx(ctx_arg)
      {
	ctx.add_thread();
      }

      ~ThreadContext()
      {
	ctx.remove_thread();
      }

    private:
      RunContext& ctx;
    };

    RunContext()
      : io_service(1),
	exit_timer(io_service),
	threads_added(0),
	threads_removed(0),
	log_context(this),
	log_wrap(),
	halt(false)
    {
      signals.reset(new ASIOSignals(io_service));
      signal_rearm();

#ifdef OPENVPN_EXIT_IN
      exit_timer.expires_at(Time::now() + Time::Duration::seconds(OPENVPN_EXIT_IN));
      exit_timer.async_wait(asio_dispatch_timer(&RunContext::exit_timer_callback, this));
#endif
    }

    void set_thread(const unsigned int unit, ThreadType* thread)
    {
      if (unit != threads.size())
	throw Exception("RunContext::set_thread: unexpected unit number");
      threads.emplace_back(thread);
    }

    // called from worker thread
    void set_server(const unsigned int unit, const typename ServerThread::Ptr& serv)
    {
      Mutex::scoped_lock lock(mutex);
      threads[unit].serv = serv;
    }

    // called from worker thread
    void clear_server(const unsigned int unit)
    {
      Mutex::scoped_lock lock(mutex);
      threads[unit].serv.reset();
    }

    void run()
    {
      if (!halt)
	{
	  io_service.run();
	}
    }

    void join()
    {
      for (size_t i = 0; i < threads.size(); ++i)
	threads[i].thread->join();
    }

    virtual void log(const std::string& str)
    {
      const std::string ts = date_time();
      {
	Mutex::scoped_lock lock(log_mutex);
	std::cout << ts << ' ' << str;
	std::cout.flush();
      }
    }

    const Log::Context::Wrapper& log_wrapper() { return log_wrap; }

    void set_stats_obj(const typename Stats::Ptr& stats_arg)
    {
      stats = stats_arg;
    }

  private:
    // called from worker thread
    void add_thread()
    {
      Mutex::scoped_lock lock(mutex);
      ++threads_added;
    }

    // called from worker thread
    void remove_thread()
    {
      Mutex::scoped_lock lock(mutex);
      ++threads_removed;
      test_completion();
    }

    void test_completion()
    {
      const size_t s = threads.size();
      if (threads_added == s && threads_removed == s)
	do_cancel();
    }

    void cancel()
    {
      Mutex::scoped_lock lock(mutex);
      do_cancel();
    }

    // may be called from worker thread
    void do_cancel()
    {
      if (!halt)
	{
	  halt = true;

	  exit_timer.cancel();

	  if (signals)
	    io_service.post(asio_dispatch_post(&ASIOSignals::cancel, signals.get()));

	  unsigned int stopped = 0;
	  for (size_t i = 0; i < threads.size(); ++i)
	    {
	      Thread& thr = threads[i];
	      if (thr.serv)
		{
		  thr.serv->thread_safe_stop();
		  ++stopped;
		}
	      thr.serv.reset();
	    }
	  OPENVPN_LOG("Stopping " << stopped << '/' << threads.size() << " thread(s)");
	}
    }

    void exit_timer_callback(const boost::system::error_code& e)
    {
      if (!e && !halt)
	{
	  cancel();
	}
    }

    void signal(const boost::system::error_code& error, int signum)
    {
      if (!error && !halt)
	{
	  OPENVPN_LOG("ASIO SIGNAL " << signum);
	  switch (signum)
	    {
	    case SIGINT:
	    case SIGTERM:
	    case SIGQUIT:
	      cancel();
	      break;
	    case SIGUSR2:
	      if (stats)
		OPENVPN_LOG(stats->dump());
	      signal_rearm();
	      break;
	    }
	}
    }

    void signal_rearm()
    {
      signals->register_signals_all(asio_dispatch_signal(&RunContext::signal, this));
    }

    boost::asio::io_service io_service;
    typename Stats::Ptr stats;
    ASIOSignals::Ptr signals;
    AsioTimer exit_timer;
    std::vector<Thread> threads;
    unsigned int threads_added;
    unsigned int threads_removed;
    Log::Context log_context;
    Log::Context::Wrapper log_wrap; // must be constructed after log_context
    Mutex mutex;
    Mutex log_mutex;
    bool halt;
  };

}

#endif
