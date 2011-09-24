#ifndef OPENVPN_COMMON_THREADPOOL_H
#define OPENVPN_COMMON_THREADPOOL_H

#if defined(BOOST_HAS_THREADS) && !defined(BOOST_ASIO_DISABLE_THREADS)
#define OPENVPN_MULTITHREAD 1
#else
#define OPENVPN_MULTITHREAD 0
#endif

#include <queue>

#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#if OPENVPN_MULTITHREAD
#include <boost/thread/thread.hpp>
#endif

#include <openvpn/common/log.hpp>


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

#if defined(BOOST_HAS_THREADS) && !defined(BOOST_ASIO_DISABLE_THREADS)
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
