//
//  tun.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TUN_LINUX_TUN_H
#define OPENVPN_TUN_LINUX_TUN_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <string>
#include <sstream>

#include <openvpn/tun/tununixbase.hpp>

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
    OPENVPN_EXCEPTION(tun_ifconfig_error);

    template <typename ReadHandler>
    class Tun : public TunUnixBase<ReadHandler, PacketFrom>
    {
      typedef TunUnixBase<ReadHandler, PacketFrom> Base;

    public:
      typedef boost::intrusive_ptr<Tun> Ptr;

      Tun(boost::asio::io_service& io_service,
	  ReadHandler read_handler_arg,
	  const Frame::Ptr& frame_arg,
	  const SessionStats::Ptr& stats_arg,
	  const std::string name,
	  const bool ipv6,
	  const Layer& layer,
	  const int txqueuelen)
	: Base(read_handler_arg, frame_arg, stats_arg)
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

	Base::name_ = ifr.ifr_name;
	Base::sd = new boost::asio::posix::stream_descriptor(io_service, fd.release());
	OPENVPN_LOG_TUN(Base::name_ << " opened for " << (ipv6 ? "IPv6" : "IPv4"));
      }

      std::string ifconfig(const OptionList& opt, const unsigned int mtu)
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
	  int status = 0;
	  const Option& o = opt.get("ifconfig");
	  o.exact_args(3);
	  const IP::Addr ip = IP::Addr::from_string(o[1], "ifconfig-ip");
	  const IP::Addr mask = IP::Addr::from_string(o[2], "ifconfig-net");
	  std::ostringstream cmd;
	  cmd << "/sbin/ifconfig " << Base::name() << ' ' << ip << " netmask " << mask << " mtu " << mtu;
	  const std::string cmd_str = cmd.str();
	  OPENVPN_LOG_TUN(cmd_str);
	  status = ::system(cmd_str.c_str());
	  if (status)
	    throw tun_ifconfig_error();
	  return ip.to_string();
	}
      }

      ~Tun() { Base::stop(); }
    };

  }
} // namespace openvpn

#endif // OPENVPN_TUN_LINUX_TUN_H
