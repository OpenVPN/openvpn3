#ifndef OPENVPN_CRYPTO_PACKET_ID_H
#define OPENVPN_CRYPTO_PACKET_ID_H

#include <string>
#include <sstream>

#include <boost/cstdint.hpp>
#include <boost/asio.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/log.hpp>
#include <openvpn/common/circ_list.hpp>
#include <openvpn/common/now.hpp>

namespace openvpn {
  namespace packet_id {
    /*
     * These are the types that members of
     * a struct packet_id_net are converted
     * to for network transmission.
     */
    typedef boost::uint32_t packet_id_type;
    typedef boost::uint32_t net_time_type;
    typedef now_t time_type;

    /*
     * In TLS mode, when a packet ID gets to this level,
     * start thinking about triggering a new
     * SSL/TLS handshake.
     */
    const packet_id_type PACKET_ID_WRAP_TRIGGER = 0xFF000000;

    /* convert a packet_id_type from host to network order */
    packet_id_type htonpid(const packet_id_type x) { return htonl(x); }

    /* convert a packet_id_type from network to host order */
    packet_id_type ntohpid(const packet_id_type x) { return ntohl(x); }

    /* convert a time_type in host order to a net_time_t in network order */
    net_time_type htontime(const time_type x) { return htonl(net_time_type(x)); }

    /* convert a net_time_type in network order to a time_type in host order */
    time_type ntohtime(const net_time_type x) { return time_type(ntohl(x)); }

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
     * a net_time_type before sending,
     * since openvpn always
     * uses a 32-bit time_t but some
     * 64 bit platforms use a
     * 64 bit time_t.
     */
    struct PacketID
    {
      time_type time;    /* converted to net_time_type before transmission */
      packet_id_type id; /* legal values are 1 through 2^32-1 */

#ifdef OPENVPN_EXTRA_LOG_INFO
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
      PacketIDConstruct(const time_type v_time = time_type(0), const packet_id_type v_id = packet_id_type(0))
      {
	time = v_time;
	id = v_id;
      }
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
       * Special time_type value that indicates that
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

      /*
       * Debug levels.
       */
      enum {
	DEBUG_QUIET=0,
	DEBUG_LOW,
	DEBUG_MEDIUM,
	DEBUG_HIGH,
	DEBUG_VERBOSE,
      };

      PacketIDReceive() : initialized_(false), seq_backtrack_(0) {}

      void init(const bool tcp_mode, const int seq_backtrack, const int time_backtrack,
		const char *name, const int unit, int debug_level)
      {
	initialized_ = false;
	debug_level_ = debug_level;
	id_ = 0;
	time_ = 0;
	last_reap_ = 0;
	seq_backtrack_ = 0;
	max_backtrack_stat_ = 0;
	time_backtrack_ = 0;
	name_ = name;
	unit_ = unit;
	if (seq_backtrack && !tcp_mode)
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
      bool test(const PacketID& pin)
      {
	// make sure we were initialized
	if (!initialized_)
	  throw packet_id_not_initialized();

	// see if we should do an expiration reap pass
	if (last_reap_ + SEQ_REAP_PERIOD <= now)
	  reap();

	// packet ID==0 is invalid
	if (!pin.id)
	  {
	    debug_log (DEBUG_LOW, pin, "ID is 0", 0);
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
		const packet_id_type diff = id_ - pin.id;

		/* keep track of maximum backtrack seen for debugging purposes */
		if (diff > max_backtrack_stat_)
		  {
		    max_backtrack_stat_ = diff;
		    debug_log (DEBUG_LOW, pin, "UDP replay-window backtrack occurred", max_backtrack_stat_);
		  }

		if (diff >= seq_list_.size())
		  {
		    debug_log (DEBUG_LOW, pin, "UDP large diff", diff);
		    return false;
		  }

		{
		  const time_type v = seq_list_[diff];
		  if (v == time_type(SEQ_UNSEEN))
		    return true;
		  else
		    {
		      /* raised from DEBUG_LOW to reduce verbosity */
		      debug_log (DEBUG_MEDIUM, pin, "UDP replay", diff);
		      return false;
		    }
		}
	      }
	    else if (pin.time < time_) /* if time goes back, reject */
	      {
		debug_log (DEBUG_LOW, pin, "UDP time backtrack", 0);
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
		    debug_log (DEBUG_MEDIUM, pin, "TCP packet ID out of sequence", 0);
		    return false;
		  }
	      }
	    else if (pin.time < time_)    /* if time goes back, reject */
	      {
		debug_log (DEBUG_LOW, pin, "TCP time backtrack", 0);
		return false;
	      }
	    else                          /* time moved forward */
	      {
		if (pin.id == 1)
		  return true;
		else
		  {
		    debug_log (DEBUG_LOW, pin, "bad initial TCP packet ID", pin.id);
		    return false;
		  }
	      }
	  }
      }

      void
      add(const PacketID& pin)
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
		seq_list_.push(time_type(SEQ_UNSEEN));
		++id_;
	      }

	    // remember timestamp of packet ID
	    {
	      const time_type local_now = now;
	      const size_t diff = id_ - pin.id;
	      if (diff < seq_list_.size() && local_now > time_type(SEQ_EXPIRED))
		seq_list_[diff] = local_now;
	    }
	  }
	else
	  {
	    // TCP mode
	    time_ = pin.time;
	    id_ = pin.id;
	  }
      }

#ifdef OPENVPN_EXTRA_LOG_INFO
      std::string str() const
      {
	std::ostringstream os;
	const time_type local_now = now;
	os << name_ << "-" << unit_ << " [";
	for (size_t i = 0; i < seq_list_.size(); ++i)
	  {
	    char c;
	    const time_type v = seq_list_[i];
	    if (v == time_type(SEQ_UNSEEN))
	      c = '_';
	    else if (v == time_type(SEQ_EXPIRED))
	      c = 'E';
	    else
	      {
		const int diff = int(local_now - v);
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
      void reap()
      {
	const time_type local_now = now;
	if (time_backtrack_)
	  {
	    bool expire = false;
	    for (size_t i = 0; i < seq_list_.size(); ++i)
	      {
		const time_type t = seq_list_[i];
		if (t == time_type(SEQ_EXPIRED)) // fast path -- once we see SEQ_EXPIRED from previous run, we can stop
		  break;
		if (!expire && t && t + time_backtrack_ < local_now)
		  expire = true;
		if (expire)
		  seq_list_[i] = time_type(SEQ_EXPIRED);
	      }
	  }
	last_reap_ = local_now;
      }

      void debug_log (const int level, const PacketID& pin, const char *description, const packet_id_type info) const
      {
	if (debug_level_ >= level)
	  do_log(pin, description, info);
      }

      void do_log (const PacketID& pin, const char *description, const packet_id_type info) const
      {
#       ifdef OPENVPN_EXTRA_LOG_INFO
	  OPENVPN_LOG("PACKET_ID: '" << description << "' pin=[" << pin.id << "," << pin.time << "] info=" << info << " state=" << str());
#       else
	  OPENVPN_LOG("PACKET_ID: '" << description << "' pin=[" << pin.id << "," << pin.time << "] info=" << info << " state=" << name_ << "-" << unit_);
#       endif
      }

      bool initialized_;                  /* true if packet_id_init was called */
      int debug_level_;                   /* log more when higher */
      packet_id_type id_;                 /* highest sequence number received */
      time_type time_;                    /* highest time stamp received */
      time_type last_reap_;               /* last call of packet_id_reap */
      packet_id_type seq_backtrack_;      /* maximum allowed packet ID backtrack (init parameter) */
      packet_id_type max_backtrack_stat_; /* maximum backtrack seen so far */
      int time_backtrack_;                /* maximum allowed time backtrack (init parameter) */
      std::string name_;                  /* name of this object (for debugging) */
      int unit_;                          /* unit number of this object (for debugging) */
      CircList<time_type> seq_list_;      /* packet-id "memory" */
    };

  } // namespace packet_id
} // namespace openvpn

#endif // OPENVPN_CRYPTO_PACKET_ID_H
