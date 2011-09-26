#ifndef OPENVPN_TUN_TUNLINUX_H
#define OPENVPN_TUN_TUNLINUX_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/weak_ptr.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/log.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/iostats.hpp>
#include <openvpn/common/dispatch.hpp>
#include <openvpn/tun/tunposix.hpp>

namespace openvpn {
  template <typename ReadHandler>
  class TunLinux
    : public TunPosix,
      public boost::enable_shared_from_this< TunLinux<ReadHandler> >
  {
  public:
    // exceptions
    OPENVPN_EXCEPTION(tun_tx_queue_len_error);

    typedef IOStats::Stats Stats;

    TunLinux(boost::asio::io_service& io_service,
	     ReadHandler read_handler,
	     const char *name=NULL,
	     const bool ipv6=false,
	     const bool tap=false,
	     const size_t buf_size=1500,
	     const int txqueuelen=200)
      : halt_(false),
	buf_size_(buf_size),
	read_handler_(read_handler)
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

      OPENVPN_LOG(name_ << " opened for " << (ipv6 ? "IPv6" : "IPv4"));
    }

    void write(Buffer* buf)
    {
      try {
	const size_t wrote = sd->write_some(buf->const_buffers_1());
	stats_.add_write_bytes(wrote);
	if (wrote != buf->size())
	  OPENVPN_LOG("TUN partial write error");
      }
      catch (boost::system::system_error& e)
	{
	  OPENVPN_LOG("TUN write error: " << e.what());
	}
    }

    Stats stats() { return stats_.get(); }
    void log() { stats_.log("TUN"); }

    void start(const int n_parallel)
    {
      for (int i = 0; i < n_parallel; i++)
	queue_read(NULL);
    }

    void stop() {
      halt_ = true;
      sd->close();
    }

    ~TunLinux() {
      delete sd;
    }

  private:
    void queue_read(BufferAllocated *buf)
    {
      //OPENVPN_LOG("TunLinux::queue_read"); // fixme
      if (!buf)
	buf = new BufferAllocated(buf_size_);

      sd->async_read_some(buf->mutable_buffers_1(),
			  asio_dispatch_read(&TunLinux::handle_read, this, buf)); // consider: this->shared_from_this()
    }

    void handle_read(BufferAllocated *buf, const boost::system::error_code& error, const size_t bytes_recvd)
    {
      //OPENVPN_LOG("TunLinux::handle_read: " << error.message()); // fixme
      ScopedPtr<BufferAllocated> sbuf(buf);
      if (!halt_)
	{
	  if (!error)
	    {
	      buf->set_size(bytes_recvd);
	      stats_.add_read_bytes(bytes_recvd);
	      try
		{
		  read_handler_(sbuf);
		}
	      catch (boost::bad_weak_ptr& e)
		{
		  return; // read handler has gone out of scope, don't requeue
		}
	    }
	  else
	    OPENVPN_LOG("TUN Read Error: " << error);
	  queue_read(sbuf.release()); // reuse buffer if still available
	}
    }

    boost::asio::posix::stream_descriptor *sd;
    bool halt_;
    const size_t buf_size_;
    ReadHandler read_handler_;
    IOStats stats_;
  };

} // namespace openvpn

#endif // OPENVPN_TUN_TUNLINUX_H
