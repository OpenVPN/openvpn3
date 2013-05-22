//
//  sessionstats.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// A class that handles statistics tracking in an OpenVPN session

#ifndef OPENVPN_LOG_SESSIONSTATS_H
#define OPENVPN_LOG_SESSIONSTATS_H

#include <cstring>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/error/error.hpp>
#include <openvpn/time/time.hpp>

namespace openvpn {

  class SessionStats : public RC<thread_safe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<SessionStats> Ptr;

    enum Stats {
      // operating stats
      BYTES_IN = 0,        // network bytes in
      BYTES_OUT,           // network bytes out
      PACKETS_IN,          // network packets in
      PACKETS_OUT,         // network packets out
      TUN_BYTES_IN,        // tun/tap bytes in
      TUN_BYTES_OUT,       // tun/tap bytes out
      TUN_PACKETS_IN,      // tun/tap packets in
      TUN_PACKETS_OUT,     // tun/tap packets out
      N_STATS,
    };

    SessionStats()
      : verbose_(false)
    {
      std::memset(stats_, 0, sizeof(stats_));
    }

    virtual void error(const size_t type, const std::string* text=NULL) = 0;

    // if true, clients may provide additional detail to error() method above
    // via text argument.
    bool verbose() const { return verbose_; }

    void inc_stat(const size_t type, const count_t value)
    {
      if (type < N_STATS)
	stats_[type] += value;
    }

    count_t get_stat(const size_t type) const
    {
      if (type < N_STATS)
	return stats_[type];
      else
	return 0;
    }

    count_t get_stat_fast(const size_t type) const
    {
      return stats_[type];
    }

    static const char *stat_name(const size_t type)
    {
      static const char *names[] = {
	"BYTES_IN",
	"BYTES_OUT",
	"PACKETS_IN",
	"PACKETS_OUT",
	"TUN_BYTES_IN",
	"TUN_BYTES_OUT",
	"TUN_PACKETS_IN",
	"TUN_PACKETS_OUT",
      };

      if (type < N_STATS)
	return names[type];
      else
	return "UNKNOWN_STAT_TYPE";
    }

    void update_last_packet_received(const Time& now)
    {
      last_packet_received_ = now;
    }

    const Time& last_packet_received() const { return last_packet_received_; }

  protected:
    void session_stats_set_verbose(const bool v) { verbose_ = v; }

  private:
    bool verbose_;
    Time last_packet_received_;
    count_t stats_[N_STATS];
  };

} // namespace openvpn

#endif // OPENVPN_LOG_SESSIONSTATS_H
