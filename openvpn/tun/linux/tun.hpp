#ifndef OPENVPN_TUN_LINUX_TUN_H
#define OPENVPN_TUN_LINUX_TUN_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <string>
#include <sstream>

#include <boost/asio.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/dispatch.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/log/protostats.hpp>
#include <openvpn/tun/tunspec.hpp>
#include <openvpn/tun/tunlog.hpp>
#include <openvpn/tun/layer.hpp>

namespace openvpn {
  namespace TunLinux {

    struct PacketFrom
    {
      typedef ScopedPtr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    // exceptions
    OPENVPN_EXCEPTION(tun_open_error);
    OPENVPN_EXCEPTION(tun_layer_error);
    OPENVPN_EXCEPTION(tun_ioctl_error);
    OPENVPN_EXCEPTION(tun_fcntl_error);
    OPENVPN_EXCEPTION(tun_name_error);
    OPENVPN_EXCEPTION(tun_tx_queue_len_error);

    template <typename ReadHandler>
    class Tun : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<Tun> Ptr;

      Tun(boost::asio::io_service& io_service,
	  ReadHandler read_handler_arg,
	  const Frame::Ptr& frame_arg,
	  const ProtoStats::Ptr& stats_arg,
	  const std::string name,
	  const bool ipv6,
	  const Layer& layer,
	  const int txqueuelen)

	: halt(false),
	  read_handler(read_handler_arg),
	  frame(frame_arg),
	  stats(stats_arg)
      {
	static const char node[] = "/dev/net/tun";
	ScopedFD fd(open(node, O_RDWR));
	if (!fd.defined())
	  OPENVPN_THROW(tun_open_error, "error opening tun device " << node << ": " << errinfo(errno));

	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_ONE_QUEUE;
	if (!ipv6)
	  ifr.ifr_flags |= IFF_NO_PI;
	if (layer() == Layer::OSI_LAYER_3)
	  ifr.ifr_flags |= IFF_TUN;
	else if (layer() == Layer::OSI_LAYER_2)
	  ifr.ifr_flags |= IFF_TAP;
	else
	  throw tun_layer_error("unknown OSI layer");
	if (!name.empty())
	  {
	    if (name.length() < IFNAMSIZ)
	      ::strcpy (ifr.ifr_name, name.c_str());
	    else
	      throw tun_name_error();
	  }

	if (ioctl (fd(), TUNSETIFF, (void *) &ifr) < 0)
	  throw tun_ioctl_error(errinfo(errno));

	if (fcntl (fd(), F_SETFL, O_NONBLOCK) < 0)
	  throw tun_fcntl_error(errinfo(errno));

	// Set the TX send queue size
	if (txqueuelen)
	  {
	    struct ifreq netifr;
	    ScopedFD ctl_fd(socket (AF_INET, SOCK_DGRAM, 0));

	    if (ctl_fd.defined())
	      {
		std::memset(&netifr, 0, sizeof(netifr));
		strcpy (netifr.ifr_name, ifr.ifr_name);
		netifr.ifr_qlen = txqueuelen;
		if (ioctl (ctl_fd(), SIOCSIFTXQLEN, (void *) &netifr) < 0)
		  throw tun_tx_queue_len_error(errinfo(errno));
	      }
	    else
	      throw tun_tx_queue_len_error(errinfo(errno));
	  }

	name_ = ifr.ifr_name;
	sd = new boost::asio::posix::stream_descriptor(io_service, fd.release());
	OPENVPN_LOG_TUN(name_ << " opened for " << (ipv6 ? "IPv6" : "IPv4"));
      }

      bool write(const Buffer& buf)
      {
	if (!halt)
	  {
	    try {
	      const size_t wrote = sd->write_some(buf.const_buffers_1());
	      stats->inc_stat(ProtoStats::TUN_BYTES_OUT, wrote);
	      if (wrote == buf.size())
		return true;
	      else
		{
		  OPENVPN_LOG_TUN_ERROR("TUN partial write error");
		  stats->error(ProtoStats::TUN_ERROR);
		  return false;
		}
	    }
	    catch (boost::system::system_error& e)
	      {
		OPENVPN_LOG_TUN_ERROR("TUN write error: " << e.what());
		stats->error(ProtoStats::TUN_ERROR);
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

      int ifconfig(const OptionList& opt, const unsigned int mtu)
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
	  const Option& o = opt.get("ifconfig");
	  o.exact_args(3);
	  const IP::Addr ip = IP::Addr::from_string(o[1], "ifconfig-ip");
	  const IP::Addr mask = IP::Addr::from_string(o[2], "ifconfig-net");
	  std::ostringstream cmd;
	  cmd << "/sbin/ifconfig " << name() << ' ' << ip << " netmask " << mask << " mtu " << mtu;
	  const std::string cmd_str = cmd.str();
	  OPENVPN_LOG_TUN(cmd_str);
	  return ::system(cmd_str.c_str());
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
	OPENVPN_LOG_TUN_VERBOSE("TunLinux::queue_read");
	if (!tunfrom)
	  tunfrom = new PacketFrom();
	frame->prepare(Frame::READ_TUN, tunfrom->buf);

	sd->async_read_some(tunfrom->buf.mutable_buffers_1(),
			    asio_dispatch_read(&Tun::handle_read, this, tunfrom));
      }

      void handle_read(PacketFrom *tunfrom, const boost::system::error_code& error, const size_t bytes_recvd)
      {
	OPENVPN_LOG_TUN_VERBOSE("TunLinux::handle_read: " << error.message());
	typename PacketFrom::SPtr pfp(tunfrom);
	if (!halt)
	  {
	    if (!error)
	      {
		pfp->buf.set_size(bytes_recvd);
		stats->inc_stat(ProtoStats::TUN_BYTES_IN, bytes_recvd);
		read_handler->tun_read_handler(pfp);
	      }
	    else
	      {
		OPENVPN_LOG_TUN_ERROR("TUN Read Error: " << error);
		stats->error(ProtoStats::TUN_ERROR);
	      }
	    queue_read(pfp.release()); // reuse buffer if still available
	  }
      }

      std::string name_;
      boost::asio::posix::stream_descriptor *sd;
      bool halt;
      ReadHandler read_handler;
      const Frame::Ptr frame;
      ProtoStats::Ptr stats;
    };

  }
} // namespace openvpn

#endif // OPENVPN_TUN_LINUX_TUN_H
