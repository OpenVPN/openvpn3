#ifndef OPENVPN_TUN_MAC_TUN_H
#define OPENVPN_TUN_MAC_TUN_H

#include <fcntl.h>
#include <errno.h>

#include <string>
#include <sstream>

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
  namespace TunMac {

    struct PacketFrom
    {
      typedef ScopedPtr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    // exceptions
    OPENVPN_EXCEPTION(tun_open_error);
    OPENVPN_EXCEPTION(tun_layer_error);
    OPENVPN_EXCEPTION(tun_fcntl_error);
    OPENVPN_EXCEPTION(tun_ifconfig_error);

    template <typename ReadHandler>
    class Tun : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<Tun> Ptr;

      Tun(boost::asio::io_service& io_service,
	  ReadHandler read_handler_arg,
	  const Frame::Ptr& frame_arg,
	  const SessionStats::Ptr& stats_arg,
	  const Layer& layer)

	: halt(false),
	  read_handler(read_handler_arg),
	  frame(frame_arg),
	  frame_context((*frame_arg)[Frame::READ_TUN]),
	  stats(stats_arg)
      {
	for (int i = 0; i < 256; ++i)
	  {
	    std::ostringstream node;
	    if (layer() == Layer::OSI_LAYER_3)
	      node << "tun";
	    else if (layer() == Layer::OSI_LAYER_2)
	      node << "tap";
	    else
	      throw tun_layer_error("unknown OSI layer");
	    node << i;
	    const std::string node_str = node.str();
	    const std::string node_fn = "/dev/" + node_str;

	    ScopedFD fd(open(node_fn.c_str(), O_RDWR));
	    if (fd.defined())
	      {
		// got it
		if (fcntl (fd(), F_SETFL, O_NONBLOCK) < 0)
		  throw tun_fcntl_error(errinfo(errno));

		name_ = node_str;
		sd = new boost::asio::posix::stream_descriptor(io_service, fd.release());
		OPENVPN_LOG_TUN(node_fn << " opened");
		return;
	      }
	  }

	OPENVPN_THROW(tun_open_error, "error opening Mac " << layer.dev_type() << " device");
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

      void stop()
      {
	if (!halt)
	  {
	    halt = true;
	    sd->close();
	    delete sd;
	  }
      }

      std::string ifconfig(const OptionList& opt, const unsigned int mtu) // fixme -- support IPv6
      {
	// first verify topology
	{
	  const Option& o = opt.get("topology");
	  o.min_args(2);
	  if (o[1] != "subnet")
	    throw option_error("only topology subnet supported");
	}

	// configure tun interface
	{
	  int status;
	  const Option& o = opt.get("ifconfig");
	  o.exact_args(3);
	  const IP::Addr ip = IP::Addr::from_string(o[1], "ifconfig-ip");
	  const IP::Addr mask = IP::Addr::from_string(o[2], "ifconfig-net");
	  {
	    std::ostringstream cmd;
	    cmd << "/sbin/ifconfig " << name() << ' ' << ip << ' ' << ip << " netmask " << mask << " mtu " << mtu << " up";
	    const std::string cmd_str = cmd.str();
	    OPENVPN_LOG_TUN(cmd_str);
	    status = ::system(cmd_str.c_str());
	  }
	  if (!status)
	    {
	      std::ostringstream cmd;
	      const IP::Addr net = ip & mask;
	      cmd << "/sbin/route add -net " << net << ' ' << ip << ' ' << mask;
	      const std::string cmd_str = cmd.str();
	      OPENVPN_LOG_TUN(cmd_str);
	      status = ::system(cmd_str.c_str());
	    }
	  if (status)
	    throw tun_ifconfig_error();
	  return ip.to_string();
	}
      }

      ~Tun() { stop(); }

      std::string name() const
      {
	return name_;
      }

    private:
      void queue_read(PacketFrom *tunfrom)
      {
	OPENVPN_LOG_TUN_VERBOSE("TunMac::queue_read");
	if (!tunfrom)
	  tunfrom = new PacketFrom();
	frame_context.prepare(tunfrom->buf);
	sd->async_read_some(frame_context.mutable_buffers_1(tunfrom->buf),
			    asio_dispatch_read(&Tun::handle_read, this, tunfrom));
      }

      void handle_read(PacketFrom *tunfrom, const boost::system::error_code& error, const size_t bytes_recvd)
      {
	OPENVPN_LOG_TUN_VERBOSE("TunMac::handle_read: " << error.message());
	PacketFrom::SPtr pfp(tunfrom);
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
      boost::asio::posix::stream_descriptor *sd;
      bool halt;
      ReadHandler read_handler;
      const Frame::Ptr frame;
      const Frame::Context& frame_context;
      SessionStats::Ptr stats;
    };

  }
} // namespace openvpn

#endif // OPENVPN_TUN_MAC_TUN_H
