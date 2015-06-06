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

// Manage a pool of threads for a multi-threaded server.
//
// To stress test this code, in client after serv->start() add:
//   if (unit == 3 || unit == 5)
//     throw Exception("HIT IT");
// And after "case PThreadBarrier::ERROR:"
//   if (unit & 1)
//     break;

#ifndef OPENVPN_COMMON_RUNCONTEXT_H
#define OPENVPN_COMMON_RUNCONTEXT_H

#include <type_traits> // for std::is_nothrow_move_constructible
#include <thread>
#include <mutex>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/asiosignal.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/common/signal.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/time/timestr.hpp>

namespace openvpn {

  struct ServerThreadBase : public RC<thread_safe_refcount>
  {
    typedef RCPtr<ServerThreadBase> Ptr;

    virtual void thread_safe_stop() = 0;
  };

  template <typename ServerThread, typename Stats>
  class RunContext : public LogBase
  {
  public:
    typedef RCPtr<RunContext> Ptr;

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
	thread_count(0),
	halt(false),
	log_context(this),
	log_wrap()
    {
      signals.reset(new ASIOSignals(io_service));
      signal_rearm();

#ifdef OPENVPN_EXIT_IN
      exit_timer.expires_at(Time::now() + Time::Duration::seconds(OPENVPN_EXIT_IN));
      exit_timer.async_wait(asio_dispatch_timer(&RunContext::exit_timer_callback, this));
#endif
    }

    void set_thread(const unsigned int unit, std::thread* thread)
    {
      while (threadlist.size() <= unit)
	threadlist.push_back(nullptr);
      if (threadlist[unit])
	throw Exception("RunContext::set_thread: overwrite");
      threadlist[unit] = thread;
    }

    // called from worker thread
    void set_server(const unsigned int unit, ServerThread* serv)
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (halt)
	throw Exception("RunContext::set_server: halting");
      while (servlist.size() <= unit)
	servlist.push_back(nullptr);
      if (servlist[unit])
	throw Exception("RunContext::set_server: overwrite");
      servlist[unit] = serv;
    }

    // called from worker thread
    void clear_server(const unsigned int unit)
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (unit < servlist.size())
	servlist[unit] = nullptr;
    }

    void run()
    {
      if (!halt)
	io_service.run();
    }

    void join()
    {
      for (size_t i = 0; i < threadlist.size(); ++i)
	{
	  std::thread* t = threadlist[i];
	  if (t)
	    {
	      t->join();
	      delete t;
	      threadlist[i] = nullptr;
	    }
	}
    }

    virtual void log(const std::string& str)
    {
      const std::string ts = date_time();
      {
	std::lock_guard<std::mutex> lock(log_mutex);
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
    // called from main or worker thread
    void add_thread()
    {
      std::lock_guard<std::mutex> lock(mutex);
      ++thread_count;
    }

    // called from main or worker thread
    void remove_thread()
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (--thread_count <= 0)
	do_cancel();
    }

    void cancel()
    {
      std::lock_guard<std::mutex> lock(mutex);
      do_cancel();
    }

    // called from main or worker thread
    void do_cancel()
    {
      if (!halt)
	{
	  halt = true;

	  exit_timer.cancel();

	  if (signals)
	    io_service.post(asio_dispatch_post(&ASIOSignals::cancel, signals.get()));

	  unsigned int stopped = 0;
	  for (size_t i = 0; i < servlist.size(); ++i)
	    {
	      ServerThread* serv = servlist[i];
	      if (serv)
		{
		  serv->thread_safe_stop();
		  ++stopped;
		}
	      servlist[i] = nullptr;
	    }
	  OPENVPN_LOG("Stopping " << stopped << '/' << servlist.size() << " thread(s)");
	}
    }

    void exit_timer_callback(const asio::error_code& e)
    {
      if (!e && !halt)
	cancel();
    }

    void signal(const asio::error_code& error, int signum)
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

    // these vars only used by main thread
    asio::io_service io_service;
    typename Stats::Ptr stats;
    ASIOSignals::Ptr signals;
    AsioTimer exit_timer;
    std::vector<std::thread*> threadlist;

    // servlist and related vars protected by mutex
    std::mutex mutex;
    std::vector<ServerThread*> servlist;
    int thread_count;
    volatile bool halt;

    // logging protected by log_mutex
    std::mutex log_mutex;
    Log::Context log_context;
    Log::Context::Wrapper log_wrap; // must be constructed after log_context
  };

}

#endif
