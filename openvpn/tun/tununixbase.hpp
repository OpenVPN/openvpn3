//
//  tununixbase.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Low level tun device class for unix-family OSes.

#ifndef OPENVPN_TUN_TUNUNIXBASE_H
#define OPENVPN_TUN_TUNUNIXBASE_H

#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/ip/ip.hpp>
#include <openvpn/common/socktypes.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/tun/tunspec.hpp>
#include <openvpn/tun/tunlog.hpp>
#include <openvpn/tun/layer.hpp>

namespace openvpn {

  template <typename ReadHandler, typename PacketFrom>
  class TunUnixBase : public RC<thread_unsafe_refcount>
  {
  public:
    TunUnixBase(ReadHandler read_handler_arg,
		const Frame::Ptr& frame_arg,
		const SessionStats::Ptr& stats_arg)
      : sd(NULL),
	retain_sd(false),
	tun_prefix(false),
	halt(false),
	read_handler(read_handler_arg),
	frame(frame_arg),
	frame_context((*frame_arg)[Frame::READ_TUN]),
	stats(stats_arg)
      {
      }

    virtual ~TunUnixBase()
    {
      stop();
      delete sd;
    }

    bool write(Buffer& buf)
    {
      if (!halt)
	{
	  try {
	    // handle tun packet prefix, if enabled
	    if (tun_prefix)
	      {
		if (buf.offset() >= 4 && buf.size() >= 1)
		  {
		    switch (IPHeader::version(buf[0]))
		      {
		      case 4:
			prepend_pf_inet(buf, PF_INET);
			break;
		      case 6:
			prepend_pf_inet(buf, PF_INET6);
			break;
		      default:
			OPENVPN_LOG_TUN_ERROR("TUN write error: cannot identify IP version for prefix");
			stats->error(Error::TUN_FRAMING_ERROR);
			return false;
		      }
		  }
		else
		  {
		    OPENVPN_LOG_TUN_ERROR("TUN write error: cannot write prefix");
		    stats->error(Error::TUN_FRAMING_ERROR);
		    return false;
		  }
	      }

	    // write data to tun device
	    const size_t wrote = sd->write_some(buf.const_buffers_1());
	    stats->inc_stat(SessionStats::TUN_BYTES_OUT, wrote);
	    stats->inc_stat(SessionStats::TUN_PACKETS_OUT, 1);
	    if (wrote == buf.size())
	      return true;
	    else
	      {
		OPENVPN_LOG_TUN_ERROR("TUN partial write error");
		stats->error(Error::TUN_WRITE_ERROR);
		return false;
	      }
	  }
	  catch (boost::system::system_error& e)
	    {
	      OPENVPN_LOG_TUN_ERROR("TUN write error: " << e.what());
	      stats->error(Error::TUN_WRITE_ERROR);
	      return false;
	    }
	}
      else
	return false;
    }

    void start(const int n_parallel)
    {
      if (!halt)
	{
	  for (int i = 0; i < n_parallel; i++)
	    queue_read(NULL);
	}
    }

    // must be called by derived class destructor
    void stop()
    {
      if (!halt)
	{
	  halt = true;
	  sd->cancel();
	  if (!retain_sd)
	    sd->close();
	  else
	    sd->release();
	}
    }

    std::string name() const
    {
      return name_;
    }

  private:
    void prepend_pf_inet(Buffer& buf, const boost::uint32_t value)
    {
      const boost::uint32_t net_value = htonl(value);
      buf.prepend((unsigned char *)&net_value, sizeof(net_value));
    }

  protected:
    void queue_read(PacketFrom *tunfrom)
    {
      OPENVPN_LOG_TUN_VERBOSE("TunUnixBase::queue_read");
      if (!tunfrom)
	tunfrom = new PacketFrom();
      frame_context.prepare(tunfrom->buf);

      // queue read on tun device
      sd->async_read_some(frame_context.mutable_buffers_1(tunfrom->buf),
			  asio_dispatch_read(&TunUnixBase::handle_read, this, tunfrom));
    }

    void handle_read(PacketFrom *tunfrom, const boost::system::error_code& error, const size_t bytes_recvd)
    {
      OPENVPN_LOG_TUN_VERBOSE("TunUnixBase::handle_read: " << error.message());
      typename PacketFrom::SPtr pfp(tunfrom);
      if (!halt)
	{
	  if (!error)
	    {
	      pfp->buf.set_size(bytes_recvd);
	      stats->inc_stat(SessionStats::TUN_BYTES_IN, bytes_recvd);
	      stats->inc_stat(SessionStats::TUN_PACKETS_IN, 1);
	      if (!tun_prefix)
		{
		  read_handler->tun_read_handler(pfp);
		}
	      else if (pfp->buf.size() >= 4)
		{
		  // handle tun packet prefix, if enabled
		  pfp->buf.advance(4);
		  read_handler->tun_read_handler(pfp);
		}
	      else
		{
		  OPENVPN_LOG_TUN_ERROR("TUN Read Error: cannot read prefix");
		  stats->error(Error::TUN_READ_ERROR);
		}
	    }
	  else
	    {
	      OPENVPN_LOG_TUN_ERROR("TUN Read Error: " << error.message());
	      stats->error(Error::TUN_READ_ERROR);
	    }
	  queue_read(pfp.release()); // reuse buffer if still available
	}
    }

    // should be set by derived class constructor
    std::string name_;
    boost::asio::posix::stream_descriptor *sd;
    bool retain_sd;  // don't close tun socket
    bool tun_prefix;

    bool halt;
    ReadHandler read_handler;
    const Frame::Ptr frame;
    const Frame::Context& frame_context;
    SessionStats::Ptr stats;
  };
}

#endif
