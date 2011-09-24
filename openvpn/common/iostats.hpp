#ifndef OPENVPN_COMMON_IOSTATS_H
#define OPENVPN_COMMON_IOSTATS_H

#include <vector>

#include <boost/asio/detail/tss_ptr.hpp>
#include <boost/asio/detail/mutex.hpp>

#include <boost/noncopyable.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/log.hpp>

namespace openvpn {

  class IOStats : private boost::noncopyable
  {
  public:
    struct Stats {
      Stats() : read_bytes(0), write_bytes(0) {}
      void add(const Stats& other)
      {
	read_bytes += other.read_bytes;
	write_bytes += other.write_bytes;
      }
      counter read_bytes;
      counter write_bytes;
    };

    void add_write_bytes(counter b)
    {
      ts_get()->write_bytes += b;
    }

    void add_read_bytes(counter b)
    {
      ts_get()->read_bytes += b;
    }

    Stats get() {
      Mutex::scoped_lock lock(mutex);
      Stats ret;
      for (StatsIterator s = stats_set.begin(); s != stats_set.end(); s++)
	ret.add(**s);
      return ret;
    }

    void log(const char *prefix)
    {
      const Stats s = get();
      OPENVPN_LOG(prefix << " bytes in: " << s.read_bytes);
      OPENVPN_LOG(prefix << " bytes out: " << s.write_bytes);      
    }

    ~IOStats() {
      Mutex::scoped_lock lock(mutex);
      for (StatsIterator s = stats_set.begin(); s != stats_set.end(); s++)
	delete *s;
    }

  private:
    typedef boost::asio::detail::mutex Mutex;
    typedef std::vector<Stats*>::iterator StatsIterator;

    Stats* ts_get()
    {
      Stats* sp = stats;
      if (!sp)
	sp = ts_alloc();
      return sp;
    }

    Stats* ts_alloc()
    {
      Mutex::scoped_lock lock(mutex);
      Stats* sp = new Stats();
      stats = sp;
      stats_set.push_back(sp);
      return sp;
    }

    boost::asio::detail::tss_ptr<Stats> stats; // lock-free access
    boost::asio::detail::mutex mutex; // only used to lock stats_set
    std::vector<Stats*> stats_set;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_IOSTATS_H
