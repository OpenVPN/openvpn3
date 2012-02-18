#ifndef OPENVPN_TUN_TUNUNIXBASE_H
#define OPENVPN_TUN_TUNUNIXBASE_H

#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/addr/ip.hpp>
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
	halt(false),
	read_handler(read_handler_arg),
	frame(frame_arg),
	frame_context((*frame_arg)[Frame::READ_TUN]),
	stats(stats_arg)
      {
      }

    bool write(const Buffer& buf)
    {
      if (!halt)
	{
	  try {
	    const size_t wrote = sd->write_some(buf.const_buffers_1());
	    stats->inc_stat(SessionStats::TUN_BYTES_OUT, wrote);
	    if (wrote == buf.size())
	      return true;
	    else
	      {
		OPENVPN_LOG_TUN_ERROR("TUN partial write error");
		stats->error(Error::TUN_ERROR);
		return false;
	      }
	  }
	  catch (boost::system::system_error& e)
	    {
	      OPENVPN_LOG_TUN_ERROR("TUN write error: " << e.what());
	      stats->error(Error::TUN_ERROR);
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
	  sd->close();
	  delete sd;
	}
    }

    std::string name() const
    {
      return name_;
    }

  protected:
    void queue_read(PacketFrom *tunfrom)
    {
      OPENVPN_LOG_TUN_VERBOSE("TunUnixBase::queue_read");
      if (!tunfrom)
	tunfrom = new PacketFrom();
      frame_context.prepare(tunfrom->buf);
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
	      read_handler->tun_read_handler(pfp);
	    }
	  else
	    {
	      OPENVPN_LOG_TUN_ERROR("TUN Read Error: " << error.message());
	      stats->error(Error::TUN_ERROR);
	    }
	  queue_read(pfp.release()); // reuse buffer if still available
	}
    }

    std::string name_;
    boost::asio::posix::stream_descriptor *sd; // must be allocated by derived class constructor
    bool halt;
    ReadHandler read_handler;
    const Frame::Ptr frame;
    const Frame::Context& frame_context;
    SessionStats::Ptr stats;
  };

}

#endif
