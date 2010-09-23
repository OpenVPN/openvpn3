#ifndef OPENVPN_TUN_TUNLINUX_H
#define OPENVPN_TUN_TUNLINUX_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <boost/noncopyable.hpp>
#include <boost/exception/all.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <iostream>

#include <openvpn/common/types.hpp>
#include <openvpn/tun/tunposix.hpp>

namespace openvpn {

class TunLinux : public TunPosix {
public:
  // exceptions
  struct tun_tx_queue_len_error : virtual error { };

  TunLinux(boost::asio::io_service& io_service,
	   const char *name=NULL,
	   const size_t buf_size=1500,
	   const bool tap=false,
	   const bool ipv6=false,
	   const int txqueuelen=200)
    : halt(false),
      n_read_pkts_(0),
      n_read_bytes_(0),
      buf_size_(buf_size)
  {
    static const char node[] = "/dev/net/tun";
    const int fd = open (node, O_RDWR);
    if (fd < 0)
      BOOST_THROW_EXCEPTION(tun_open_error()
			    << boost::errinfo_errno(errno)
			    << boost::errinfo_file_name(node));

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
	    BOOST_THROW_EXCEPTION(tun_name_error());
	  }
      }

    if (::ioctl (fd, TUNSETIFF, (void *) &ifr) < 0)
      {
	const int errno_save = errno;
	close(fd);
	BOOST_THROW_EXCEPTION(tun_ioctl_error() << boost::errinfo_errno(errno_save));
      }

    if (::fcntl (fd, F_SETFL, O_NONBLOCK) < 0)
      {
	const int errno_save = errno;
	close(fd);
	BOOST_THROW_EXCEPTION(tun_fcntl_error() << boost::errinfo_errno(errno_save));
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
	    if (::ioctl (ctl_fd, SIOCSIFTXQLEN, (void *) &netifr) >= 0)
	      {
		close (ctl_fd);
	      }
	    else
	      {
		const int errno_save = errno;
		close (fd);
		close (ctl_fd);
		BOOST_THROW_EXCEPTION(tun_tx_queue_len_error() << boost::errinfo_errno(errno_save));
	      }
	  }
	else
	  {
	    const int errno_save = errno;
	    close (fd);
	    BOOST_THROW_EXCEPTION(tun_tx_queue_len_error() << boost::errinfo_errno(errno_save));
	  }
      }

    name_ = ifr.ifr_name;

    sd = new boost::asio::posix::stream_descriptor(io_service, fd);
    queue_read();
  }

  openvpn::counter n_read_pkts(void) const { return n_read_pkts_; }
  openvpn::counter n_read_bytes(void) const { return n_read_bytes_; }

  void stop(void) {
    halt = true;
    sd->close();
  }

  virtual ~TunLinux() {
    delete sd;
  }

private:
  void queue_read(void)
  {
    buffer_ptr buf(new buffer(buf_size_));

    sd->async_read_some(buf->mutable_buffers_1(),
			boost::bind(&TunLinux::handle_read,
				    this,
				    buf,
				    boost::asio::placeholders::error,
				    boost::asio::placeholders::bytes_transferred));
  }

  void handle_read(buffer_ptr buf, const boost::system::error_code& error, const size_t bytes_recvd)
  {
    if (!halt)
      {
	if (!error)
	  {
	    buf->set_size(bytes_recvd);
	    ++n_read_pkts_;
	    n_read_bytes_ += bytes_recvd;
	    // todo: dispatch packet
	  }
	else
	  std::cout << "TUN Read Error: " << error << std::endl;
	queue_read();
      }
  }

  boost::asio::posix::stream_descriptor *sd;
  openvpn::counter n_read_pkts_;
  openvpn::counter n_read_bytes_;
  bool halt;
  const size_t buf_size_;
};

} // namespace openvpn

#endif // OPENVPN_TUN_TUNLINUX_H
