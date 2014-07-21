//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

// Manage OpenVPN protocol Packet IDs for packet replay detection

#ifndef OPENVPN_CRYPTO_PACKET_ID_H
#define OPENVPN_CRYPTO_PACKET_ID_H

#include <string>
#include <sstream>

#include <boost/cstdint.hpp> // for boost::uint32_t
#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/circ_list.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/log/sessionstats.hpp>

namespace openvpn {
  /*
   * Communicate packet-id over the wire.
   * A short packet-id is just a 32 bit
   * sequence number.  A long packet-id
   * includes a timestamp as well.
   *
   * Long packet-ids are used as IVs for
   * CFB/OFB ciphers.
   *
   * This data structure is always sent
   * over the net in network byte order,
   * by calling htonpid, ntohpid,
   * htontime, and ntohtime on the
   * data elements to change them
   * to and from standard sizes.
   *
   * In addition, time is converted to
   * a PacketID::net_time_t before sending,
   * since openvpn always
   * uses a 32-bit time_t but some
   * 64 bit platforms use a
   * 64 bit time_t.
   */
  struct PacketID
  {
    typedef boost::uint32_t id_t;
    typedef boost::uint32_t net_time_t;
    typedef Time::base_type time_t;

    enum {
      SHORT_FORM = 0, // short form of ID (4 bytes)
      LONG_FORM = 1,  // long form of ID (8 bytes)

      UNDEF = 0,       // special undefined/null id_t value
    };

    id_t id;       // legal values are 1 through 2^32-1
    time_t time;   // converted to PacketID::net_time_t before transmission

    static size_t size(const int form)
    {
      if (form == PacketID::LONG_FORM)
	return sizeof(id_t) + sizeof(net_time_t);
      else
	return sizeof(id_t);
    }

    bool is_valid() const
    {
      return id != UNDEF;
    }

    void reset()
    {
      id = id_t(0);
      time = time_t(0);
    }

    void read(Buffer& buf, const int form)
    {
      id_t net_id;
      net_time_t net_time;

      buf.read ((unsigned char *)&net_id, sizeof (net_id));
      id = ntohl (net_id);

      if (form == LONG_FORM)
	{
	  buf.read ((unsigned char *)&net_time, sizeof (net_time));
	  time = ntohl (net_time);
	}
      else
	time = time_t(0);
    }

    void write(Buffer& buf, const int form, const bool prepend) const
    {
      const id_t net_id = htonl(id);
      const net_time_t net_time = htonl(time);

      if (prepend)
	{
	  if (form == LONG_FORM)
	    buf.prepend ((unsigned char *)&net_time, sizeof (net_time));
	  buf.prepend ((unsigned char *)&net_id, sizeof (net_id));
	}
      else
	{
	  buf.write ((unsigned char *)&net_id, sizeof (net_id));
	  if (form == LONG_FORM)
	    buf.write ((unsigned char *)&net_time, sizeof (net_time));
	}
    }

#ifdef OPENVPN_INSTRUMENTATION
    std::string str() const
    {
      std::ostringstream os;
      os << "[" << time << "," << id << "]";
      return os.str();
    }
#endif
  };

  struct PacketIDConstruct : public PacketID
  {
    PacketIDConstruct(const PacketID::time_t v_time = PacketID::time_t(0), const PacketID::id_t v_id = PacketID::id_t(0))
    {
      id = v_id;
      time = v_time;
    }
  };

  class PacketIDSend
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(packet_id_wrap);

    PacketIDSend()
    {
      init(PacketID::SHORT_FORM);
    }

    void init(const int form) // PacketID::LONG_FORM or PacketID::SHORT_FORM
    {
      pid_.id = PacketID::id_t(0);
      pid_.time = PacketID::time_t(0);
      form_ = form;
    }

    PacketID next(const PacketID::time_t now)
    {
      PacketID ret;
      if (!pid_.time)
	pid_.time = now;
      ret.id = ++pid_.id;
      if (!pid_.id) // wraparound
	{
	  if (form_ != PacketID::LONG_FORM)
	    throw packet_id_wrap();
	  pid_.time = now;
	  ret.id = pid_.id = 1;
	}
      ret.time = pid_.time;
      return ret;
    }

    void write_next(Buffer& buf, const bool prepend, const PacketID::time_t now)
    {
      const PacketID pid = next(now);
      pid.write(buf, form_, prepend);
    }

    /*
     * In TLS mode, when a packet ID gets to this level,
     * start thinking about triggering a new
     * SSL/TLS handshake.
     */
    bool wrap_warning() const
    {
      const PacketID::id_t wrap_at = 0xFF000000;
      return pid_.id >= wrap_at;
    }

#ifdef OPENVPN_INSTRUMENTATION
    std::string str() const
    {
      std::string ret;
      ret = pid_.str();
      if (form_ == PacketID::LONG_FORM)
	ret += 'L';
      return ret;
    }
#endif

  private:
    PacketID pid_;
    int form_;
  };

  /*
   * This is the data structure we keep on the receiving side,
   * to check that no packet-id (i.e. sequence number + optional timestamp)
   * is accepted more than once.
   */
  class PacketIDReceive
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(packet_id_backtrack_out_of_range);
    OPENVPN_SIMPLE_EXCEPTION(packet_id_not_initialized);

    /*
     * Maximum allowed backtrack in
     * sequence number due to packets arriving
     * out of order.
     */
    enum {
      MIN_SEQ_BACKTRACK = 0,
      MAX_SEQ_BACKTRACK = 65536,
      DEFAULT_SEQ_BACKTRACK = 64
    };

    /*
     * Maximum allowed backtrack in
     * seconds due to packets arriving
     * out of order.
     */
    enum {
      MIN_TIME_BACKTRACK = 0,
      MAX_TIME_BACKTRACK = 600,
      DEFAULT_TIME_BACKTRACK = 15
    };

    /*
     * Special PacketID::time_t value that indicates that
     * sequence number has expired.
     */
    enum {
      SEQ_UNSEEN = 0,
      SEQ_EXPIRED = 1
    };

    /*
     * Do a reap pass through the sequence number
     * array once every n seconds in order to
     * expire sequence numbers which can no longer
     * be accepted because they would violate
     * TIME_BACKTRACK.
     */
    enum {
      SEQ_REAP_PERIOD = 5
    };

    /* mode */
    enum {
      UDP_MODE = 0,
      TCP_MODE = 1
    };

    PacketIDReceive() : initialized_(false) {}

    bool initialized() const { return initialized_; }

    void init(const int mode, const int form,
	      const int seq_backtrack, const int time_backtrack,
	      const char *name, const int unit,
	      const SessionStats::Ptr& stats_arg)
    {
      initialized_ = false;
      form_ = form;
      id_ = 0;
      time_ = 0;
      last_reap_ = 0;
      seq_backtrack_ = 0;
      max_backtrack_stat_ = 0;
      time_backtrack_ = 0;
      name_ = name;
      unit_ = unit;
      stats = stats_arg;
      if (seq_backtrack && mode == UDP_MODE)
	{
	  if (MIN_SEQ_BACKTRACK <= seq_backtrack
	      && seq_backtrack <= MAX_SEQ_BACKTRACK
	      && MIN_TIME_BACKTRACK <= time_backtrack
	      && time_backtrack <= MAX_TIME_BACKTRACK)
	    {
	      seq_backtrack_ = seq_backtrack;
	      time_backtrack_ = time_backtrack;
	      seq_list_.init(seq_backtrack);
	    }
	  else
	    throw packet_id_backtrack_out_of_range();
	}
      else
	seq_list_.init(0);
      initialized_ = true;
    }

    /*
     * Return true if packet id is ok, or false if
     * it's a replay.
     */
    bool test(const PacketID& pin, const PacketID::time_t now)
    {
      // make sure we were initialized
      if (!initialized_)
	throw packet_id_not_initialized();

      // see if we should do an expiration reap pass
      if (last_reap_ + SEQ_REAP_PERIOD <= now)
	reap(now);

      // test for invalid packet ID
      if (!pin.is_valid())
	{
	  debug_log (Error::PKTID_INVALID, pin, "PID is invalid", 0, now);
	  return false;
	}

      if (seq_list_.defined())
	{
	  /*
	   * In backtrack mode, we allow packet reordering subject
	   * to the seq_backtrack and time_backtrack constraints.
	   *
	   * This mode is used with UDP.
	   */
	  if (pin.time == time_)
	    {
	      /* is packet-id greater than any one we've seen yet? */
	      if (pin.id > id_)
		return true;

	      /* check packet-id sliding window for original/replay status */
	      const PacketID::id_t diff = id_ - pin.id;

	      /* keep track of maximum backtrack seen for debugging purposes */
	      if (diff > max_backtrack_stat_)
		{
		  max_backtrack_stat_ = diff;
		  debug_log (Error::PKTID_UDP_REPLAY_WINDOW_BACKTRACK, pin, "UDP replay-window backtrack occurred", max_backtrack_stat_, now);
		}

	      if (diff >= seq_list_.size())
		{
		  debug_log (Error::PKTID_UDP_LARGE_DIFF, pin, "UDP large diff", diff, now);
		  return false;
		}

	      {
		const PacketID::time_t v = seq_list_[diff];
		if (v == PacketID::time_t(SEQ_UNSEEN))
		  return true;
		else
		  {
		    debug_log (Error::PKTID_UDP_REPLAY, pin, "UDP replay", diff, now);
		    return false;
		  }
	      }
	    }
	  else if (pin.time < time_) /* if time goes back, reject */
	    {
	      debug_log (Error::PKTID_UDP_TIME_BACKTRACK, pin, "UDP time backtrack", 0, now);
	      return false;
	    }
	  else                       /* time moved forward */
	    return true;
	}
      else
	{
	  /*
	   * In non-backtrack mode, all sequence number series must
	   * begin at some number n > 0 and must increment linearly without gaps.
	   *
	   * This mode is used with TCP.
	   */
	  if (pin.time == time_)
	    {
	      if (pin.id == id_ + 1)
		return true;
	      else
		{
		  debug_log (Error::PKTID_TCP_OUT_OF_SEQ, pin, "TCP packet ID out of sequence", 0, now);
		  return false;
		}
	    }
	  else if (pin.time < time_)    /* if time goes back, reject */
	    {
	      debug_log (Error::PKTID_TCP_TIME_BACKTRACK, pin, "TCP time backtrack", 0, now);
	      return false;
	    }
	  else                          /* time moved forward */
	    {
	      if (pin.id == 1)
		return true;
	      else
		{
		  debug_log (Error::PKTID_TCP_BAD_INITIAL, pin, "bad initial TCP packet ID", 0, now);
		  return false;
		}
	    }
	}
    }

    void
    add(const PacketID& pin, const PacketID::time_t now)
    {
      if (!initialized_)
	throw packet_id_not_initialized();
      if (seq_list_.defined())
	{
	  // UDP mode.  Decide if we should reset sequence number history list.
	  if (!seq_list_.size()            // indicates first pass
	      || pin.time > time_          // if time value increases, must reset
	      || (pin.id >= seq_backtrack_ // also, big jumps in pin.id require us to reset
		  && pin.id - seq_backtrack_ > id_))
	    {
	      time_ = pin.time;
	      id_ = 0;
	      if (pin.id > seq_backtrack_) // if pin.id is large, fast-forward
		id_ = pin.id - seq_backtrack_;
	      seq_list_.reset();
	    }

	  while (id_ < pin.id) // should never iterate more than seq_backtrack_ steps
	    {
	      seq_list_.push(PacketID::time_t(SEQ_UNSEEN));
	      ++id_;
	    }

	  // remember timestamp of packet ID
	  {
	    const size_t diff = id_ - pin.id;
	    if (diff < seq_list_.size() && now > PacketID::time_t(SEQ_EXPIRED))
	      seq_list_[diff] = now;
	  }
	}
      else
	{
	  // TCP mode
	  time_ = pin.time;
	  id_ = pin.id;
	}
    }

    PacketID read_next(Buffer& buf) const
    {
      if (!initialized_)
	throw packet_id_not_initialized();
      PacketID pid;
      pid.read(buf, form_);
      return pid;
    }

#ifdef OPENVPN_INSTRUMENTATION
    std::string str(const PacketID::time_t now) const
    {
      if (!initialized_)
	throw packet_id_not_initialized();
      std::ostringstream os;
      os << name_ << "-" << unit_ << " [";
      for (size_t i = 0; i < seq_list_.size(); ++i)
	{
	  char c;
	  const PacketID::time_t v = seq_list_[i];
	  if (v == PacketID::time_t(SEQ_UNSEEN))
	    c = '_';
	  else if (v == PacketID::time_t(SEQ_EXPIRED))
	    c = 'E';
	  else
	    {
	      const int diff = int(now - v);
	      if (diff < 0)
		c = 'N';
	      else if (diff < 10)
		c = '0' + diff;
	      else
		c = '>';
	    }
	  os << c;
	}
      os << "] " << time_ << ":" << id_;
      return os.str();
    }
#endif

  private:
    /*
     * Expire sequence numbers which can no longer
     * be accepted because they would violate
     * time_backtrack.
     */
    void reap(const PacketID::time_t now)
    {
      if (time_backtrack_)
	{
	  bool expire = false;
	  for (size_t i = 0; i < seq_list_.size(); ++i)
	    {
	      const PacketID::time_t t = seq_list_[i];
	      if (t == PacketID::time_t(SEQ_EXPIRED)) // fast path -- once we see SEQ_EXPIRED from previous run, we can stop
		break;
	      if (!expire && t && t + time_backtrack_ < now)
		expire = true;
	      if (expire)
		seq_list_[i] = PacketID::time_t(SEQ_EXPIRED);
	    }
	}
      last_reap_ = now;
    }

    void debug_log (const Error::Type err_type, const PacketID& pin, const char *description, const PacketID::id_t info, const PacketID::time_t now) const
    {
#ifdef OPENVPN_INSTRUMENTATION
      if (stats->verbose())
	{
	  const std::string text = fmt_info(pin, description, info, now);
	  stats->error(err_type, &text);
	}
      else
#endif
      stats->error(err_type);
    }

#ifdef OPENVPN_INSTRUMENTATION
    std::string fmt_info (const PacketID& pin, const char *description, const PacketID::id_t info, const PacketID::time_t now) const
    {
      std::ostringstream os;
      os << description << " pin=[" << pin.time << "," << pin.id << "] info=" << info << " state=" << str(now);
      return os.str();
    }
#endif

    bool initialized_;                     /* true if packet_id_init was called */
    PacketID::id_t id_;                    /* highest sequence number received */
    PacketID::time_t time_;                /* highest time stamp received */
    PacketID::time_t last_reap_;           /* last call of packet_id_reap */
    PacketID::id_t seq_backtrack_;         /* maximum allowed packet ID backtrack (init parameter) */
    PacketID::id_t max_backtrack_stat_;    /* maximum backtrack seen so far */
    int time_backtrack_;                   /* maximum allowed time backtrack (init parameter) */
    std::string name_;                     /* name of this object (for debugging) */
    int unit_;                             /* unit number of this object (for debugging) */
    int form_;                             /* PacketID::LONG_FORM or PacketID::SHORT_FORM */
    SessionStats::Ptr stats;               /* used for error logging */
    CircList<PacketID::time_t> seq_list_;  /* packet-id "memory" */
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_PACKET_ID_H
