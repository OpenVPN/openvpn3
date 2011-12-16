#ifndef OPENVPN_TUN_LINUX_TUNLINUX_H
#define OPENVPN_TUN_LINUX_TUNLINUX_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <string>
#include <sstream>

#include <boost/asio.hpp>
#include <boost/weak_ptr.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/dispatch.hpp>
#include <openvpn/common/parseopt.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/tun/tunposix.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/log.hpp>
#include <openvpn/log/protostats.hpp>
#include <openvpn/addr/ip.hpp>

#ifdef OPENVPN_DEBUG_TUNLINUX
#define OPENVPN_LOG_TUNLINUX(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_TUNLINUX(x)
#endif

namespace openvpn {
  template <typename ReadHandler>
  class TunLinux : public TunPosix
  {
  public:
    // exceptions
    OPENVPN_EXCEPTION(tun_tx_queue_len_error);

    TunLinux(boost::asio::io_service& io_service,
	     ReadHandler read_handler,
	     const Frame::Ptr& frame,
	     const ProtoStats::Ptr& stats,
	     const char *name=NULL,
	     const bool ipv6=false,
	     const bool tap=false,
	     const int txqueuelen=200)
      : halt_(false),
	read_handler_(read_handler),
	frame_(frame),
	stats_(stats)
    {
      static const char node[] = "/dev/net/tun";
      const int fd = open (node, O_RDWR);
      if (fd < 0)
	OPENVPN_THROW(tun_open_error, "error opening tun device " << node << ": " << errinfo(errno));

      struct ifreq ifr;
      std::memset(&ifr, 0, sizeof(ifr));
      ifr.ifr_flags = IFF_ONE_QUEUE;
      if (!ipv6)
	ifr.ifr_flags |= IFF_NO_PI;
      if (tap)
	ifr.ifr_flags |= IFF_TAP;
      else
	ifr.ifr_flags |= IFF_TUN;
      if (name)
	{
	  if (::strlen(name) < IFNAMSIZ)
	    ::strcpy (ifr.ifr_name, name);
	  else
	    {
	      close(fd);
	      throw tun_name_error();
	    }
	}

      if (ioctl (fd, TUNSETIFF, (void *) &ifr) < 0)
	{
	  const int errno_save = errno;
	  close(fd);
	  throw tun_ioctl_error(errinfo(errno_save));
	}

      if (fcntl (fd, F_SETFL, O_NONBLOCK) < 0)
	{
	  const int errno_save = errno;
	  close(fd);
	  throw tun_fcntl_error(errinfo(errno_save));
	}

      // Set the TX send queue size
      if (txqueuelen)
	{
	  struct ifreq netifr;
	  int ctl_fd;

	  if ((ctl_fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0)
	    {
	      std::memset(&netifr, 0, sizeof(netifr));
	      strcpy (netifr.ifr_name, ifr.ifr_name);
	      netifr.ifr_qlen = txqueuelen;
	      if (ioctl (ctl_fd, SIOCSIFTXQLEN, (void *) &netifr) >= 0)
		{
		  close (ctl_fd);
		}
	      else
		{
		  const int errno_save = errno;
		  close (fd);
		  close (ctl_fd);
		  throw tun_tx_queue_len_error(errinfo(errno_save));
		}
	    }
	  else
	    {
	      const int errno_save = errno;
	      close (fd);
	      throw tun_tx_queue_len_error(errinfo(errno_save));
	    }
	}

      name_ = ifr.ifr_name;

      sd = new boost::asio::posix::stream_descriptor(io_service, fd);

      OPENVPN_LOG_TUNLINUX(name_ << " opened for " << (ipv6 ? "IPv6" : "IPv4"));
    }

    bool write(const Buffer& buf)
    {
      try {
	const size_t wrote = sd->write_some(buf.const_buffers_1());
	stats_->inc_stat(ProtoStats::TUN_BYTES_OUT, wrote);
	if (wrote == buf.size())
	  return true;
	else
	  {
	    OPENVPN_LOG_TUNLINUX("TUN partial write error");
	    stats_->error(ProtoStats::TUN_ERROR);
	    return false;
	  }
      }
      catch (boost::system::system_error& e)
	{
	  OPENVPN_LOG_TUNLINUX("TUN write error: " << e.what());
	  stats_->error(ProtoStats::TUN_ERROR);
	  return false;
	}
    }

    void start(const int n_parallel)
    {
      for (int i = 0; i < n_parallel; i++)
	queue_read(NULL);
    }

    void stop() {
      halt_ = true;
      sd->close();
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
	std::string ip = validate_ip_address("ifconfig-ip", o[1]);
	std::string mask = validate_ip_address("ifconfig-net", o[2]);
	std::ostringstream cmd;
	cmd << "/sbin/ifconfig " << name() << ' ' << ip << " netmask " << mask << " mtu " << mtu;
	const std::string cmd_str = cmd.str();
	OPENVPN_LOG(cmd_str);
	return ::system(cmd_str.c_str());
      }
    }

    ~TunLinux() {
      delete sd;
    }

  private:
    void queue_read(BufferAllocated *buf)
    {
      //OPENVPN_LOG_TUNLINUX("TunLinux::queue_read");
      if (!buf)
	buf = new BufferAllocated();
      frame_->prepare(Frame::READ_TUN, *buf);

      sd->async_read_some(buf->mutable_buffers_1(),
			  asio_dispatch_read(&TunLinux::handle_read, this, buf)); // consider: this->shared_from_this()
    }

    void handle_read(BufferAllocated *buf, const boost::system::error_code& error, const size_t bytes_recvd)
    {
      //OPENVPN_LOG_TUNLINUX("TunLinux::handle_read: " << error.message());
      ScopedPtr<BufferAllocated> sbuf(buf);
      if (!halt_)
	{
	  if (!error)
	    {
	      buf->set_size(bytes_recvd);
	      stats_->inc_stat(ProtoStats::TUN_BYTES_IN, bytes_recvd);
	      read_handler_(sbuf);
	    }
	  else
	    {
	      OPENVPN_LOG_TUNLINUX("TUN Read Error: " << error);
	      stats_->error(ProtoStats::TUN_ERROR);
	    }
	  queue_read(sbuf.release()); // reuse buffer if still available
	}
    }

    boost::asio::posix::stream_descriptor *sd;
    bool halt_;
    ReadHandler read_handler_;
    const Frame::Ptr frame_;
    ProtoStats::Ptr stats_;
  };

} // namespace openvpn

#endif // OPENVPN_TUN_LINUX_TUNLINUX_H
