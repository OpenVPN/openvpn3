#ifndef OPENVPN_COMMON_THREADPOOL_H
#define OPENVPN_COMMON_THREADPOOL_H

#include <queue>

#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/thread.hpp>

namespace openvpn {

  class ASIOThreadPool
  {
  public:
    explicit ASIOThreadPool(boost::asio::io_service& io_service)
      : io_service_(io_service) {}

    void run()
    {
      io_service_.run();
    }

    void run_multithread(size_t n_threads)
    {
      if (n_threads)
	{
#if OPENVPN_MULTITHREAD
	  run_multithread_async(n_threads);
	  join();
#else
	  OPENVPN_LOG("ThreadPool: running single ASIO thread because multithreading is disabled");
	  run();
#endif
	}
      else
	run();
    }

#if OPENVPN_MULTITHREAD
  private:
    typedef boost::shared_ptr<boost::thread> threadptr;
    std::queue<threadptr> threads_;

  public:
    void run_multithread_async(size_t n_threads)
    {
      for (size_t i = 0; i < n_threads; ++i)
	{
	  threadptr thread(new boost::thread(boost::bind(&boost::asio::io_service::run, &io_service_)));
	  threads_.push(thread);
	}
    }

    void join()
    {
      while (!threads_.empty())
	{
	  threads_.front()->join();
	  threads_.pop();
	}
    }
#endif

public:
    boost::asio::io_service& io_service_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_THREADPOOL_H
