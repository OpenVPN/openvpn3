#ifndef OPENVPN_COMMON_IOSTATS_H
#define OPENVPN_COMMON_IOSTATS_H

#include <vector>

#include <boost/noncopyable.hpp>

#include <openvpn/common/thread.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/log.hpp>

namespace openvpn {

  struct RWStats {
    RWStats() : read_bytes(0), write_bytes(0) {}
    void add(const RWStats& other)
    {
      read_bytes += other.read_bytes;
      write_bytes += other.write_bytes;
    }
    void log(const char *prefix) const
    {
      OPENVPN_LOG(prefix << " bytes in: " << read_bytes);
      OPENVPN_LOG(prefix << " bytes out: " << write_bytes);      
    }
    count_t read_bytes;
    count_t write_bytes;
  };

class IOStatsSingleThread
{
public:
    void add_write_bytes(const count_t b)
    {
      stats_.write_bytes += b;
    }

    void add_read_bytes(const count_t b)
    {
      stats_.read_bytes += b;
    }

    RWStats get() const {
      return stats_;
    }

    void log(const char *prefix) const
    {
      stats_.log(prefix);
    }
private:
  RWStats stats_;
};

#if OPENVPN_MULTITHREAD
  class IOStatsMultiThread : private boost::noncopyable
  {
  public:
    void add_write_bytes(const count_t b)
    {
      ts_get()->write_bytes += b;
    }

    void add_read_bytes(const count_t b)
    {
      ts_get()->read_bytes += b;
    }

    RWStats get() {
      Mutex::scoped_lock lock(mutex);
      RWStats ret;
      for (StatsIterator s = stats_set.begin(); s != stats_set.end(); s++)
	ret.add(**s);
      return ret;
    }

    void log(const char *prefix)
    {
      const RWStats s = get();
      s.log(prefix);
    }

    ~IOStatsMultiThread() {
      Mutex::scoped_lock lock(mutex);
      for (StatsIterator s = stats_set.begin(); s != stats_set.end(); s++)
	delete *s;
    }

  private:
    typedef boost::asio::detail::mutex Mutex;
    typedef std::vector<RWStats*>::const_iterator StatsIterator;

    RWStats* ts_get()
    {
      RWStats* sp = stats;
      if (!sp)
	sp = ts_alloc();
      return sp;
    }

    RWStats* ts_alloc()
    {
      Mutex::scoped_lock lock(mutex);
      RWStats* sp = new RWStats();
      stats = sp;
      stats_set.push_back(sp);
      return sp;
    }

    boost::asio::detail::tss_ptr<RWStats> stats; // lock-free access
    boost::asio::detail::mutex mutex; // only used to lock stats_set
    std::vector<RWStats*> stats_set;
  };
#endif

} // namespace openvpn

#endif // OPENVPN_COMMON_IOSTATS_H
