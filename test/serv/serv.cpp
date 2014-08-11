#include <iostream>
#include <string>

#include <boost/bind.hpp>

#include <openvpn/log/logsimple.hpp>

#include <openvpn/time/asiotimer.hpp> // fixme

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/thread.hpp>
#include <openvpn/common/thread.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/asiosignal.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/init/initprocess.hpp>

using namespace openvpn;

class ServerThread : public RC<thread_unsafe_refcount>
{
public:
  typedef boost::intrusive_ptr<ServerThread> Ptr;

  struct Config
  {
  };

  ServerThread(boost::asio::io_service& io_service_arg,
	       const Config& config_arg)
    : io_service(io_service_arg),
      config(config_arg)
  {
  }

  void start()
  {
  }

  void stop()
  {
  }

  void thread_safe_stop()
  {
  }

private:
  boost::asio::io_service& io_service;
  Config config;
};

class MyRunContext : public RC<thread_safe_refcount>
{
public:
  typedef boost::intrusive_ptr<MyRunContext> Ptr;

  MyRunContext(ServerThread::Ptr& serv_arg)
    : io_service(1),
      signals(new ASIOSignals(io_service)),
      serv(serv_arg),
      debug_timer(io_service), // fixme
      halt(false)
  {
    signals->register_signals(asio_dispatch_signal(&MyRunContext::signal, this));
  }

  void run()
  {
    if (!halt)
      {
	schedule_debug_timer(); // fixme
	io_service.run();
      }
  }

  void cancel()
  {
    if (!halt)
      {
	halt = true;
	OPENVPN_LOG("CANCEL"); // fixme
	io_service.post(asio_dispatch_post(&ASIOSignals::cancel, signals.get()));
      }
  }

private:
  void signal(const boost::system::error_code& error, int signal_number)
  {
    if (!error && !halt)
      {
	OPENVPN_LOG("ASIO SIGNAL " << signal_number); // fixme
	if (serv)
	  serv->thread_safe_stop();
	debug_timer.cancel(); // fixme
      }
  }

  void debug_timeout_handler(const boost::system::error_code& e) // called by Asio
  {
    if (!e)
      {
	OPENVPN_LOG("DBG TIMER FIRED"); // fixme
	cancel();
      }
  }

  void schedule_debug_timer() // fixme
  {
    OPENVPN_LOG("SCHED DBG TIMER"); // fixme
    debug_timer.expires_at(Time::now() + Time::Duration::seconds(5)); // fixme
    debug_timer.async_wait(asio_dispatch_timer(&MyRunContext::debug_timeout_handler, this)); // fixme
  }

  boost::asio::io_service io_service;
  ASIOSignals::Ptr signals;
  ServerThread::Ptr& serv;

  AsioTimer debug_timer; // fixme
  bool halt;
};

void work(const char *config_fn, ServerThread::Ptr& serv)
{
  // parse options from server config file
  OptionList opt = OptionList::parse_from_config_static(read_text(config_fn), NULL);

  // set up server config
  ServerThread::Config server_config;

  // initialize the Asio io_service object (for worker thread)
  boost::asio::io_service io_service(1); // concurrency hint=1

  // instantiate top-level server session
  serv.reset(new ServerThread(io_service, server_config));

  // start VPN
  serv->start(); // queue parallel async reads

  // run i/o reactor
  try {
    io_service.run();
  }
  catch (const std::exception&)
    {
      serv->stop();      // on exception, stop server,
      io_service.poll(); //   execute completion handlers,
      throw;             //   and rethrow exception
    }
}

void worker_thread(const char *config_fn, ServerThread::Ptr& serv, MyRunContext::Ptr run_context)
{
  boost::asio::detail::signal_blocker signal_blocker; // signals should be handled by parent thread
  try {
    std::cout << "WORKER THREAD STARTING" << std::endl;
    work(config_fn, serv);
  }
  catch (const std::exception& e)
    {
      std::cerr << "Worker thread exception: " << e.what() << std::endl;
    }
  //run_context->cancel(); // fixme
}

int main(int argc, char* argv[])
{
  int ret = 0;
  boost::thread* thread = NULL;

  // process-wide initialization
  InitProcess::init();

  try {
    if (argc >= 2)
      {
	// start worker thread
	ServerThread::Ptr serv;
	MyRunContext::Ptr run_context = new MyRunContext(serv);
	const char *config_fn = argv[1];
	thread = new boost::thread(boost::bind(&worker_thread, config_fn, boost::ref(serv), run_context));

	// wait for worker to exit
	run_context->run();
	thread->join();
      }
    else
      {
	std::cerr << "OpenVPN Server (C++ core)" << std::endl;
	std::cerr << "usage: " << argv[0] << " <config-file>" << std::endl;
	ret = 2;
      }
  }
  catch (const std::exception& e)
    {
      std::cerr << "Main thread exception: " << e.what() << std::endl;
      ret = 1;
    }

  delete thread;
  InitProcess::uninit();
  return ret;
}
