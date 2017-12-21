//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
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

// Low-level tun interface driver for Linux, client/server independent.

#ifndef OPENVPN_TUN_LINUX_TUN_H
#define OPENVPN_TUN_LINUX_TUN_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <string>
#include <sstream>
#include <memory>

#include <openvpn/asio/asioerr.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/common/to_string.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/tun/tunio.hpp>
#include <openvpn/tun/layer.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/frame/frame.hpp>

namespace openvpn {
  namespace TunLinux {

    struct PacketFrom
    {
      typedef std::unique_ptr<PacketFrom> SPtr;
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
    class Tun : public TunIO<ReadHandler, PacketFrom, openvpn_io::posix::stream_descriptor>
    {
      typedef TunIO<ReadHandler, PacketFrom, openvpn_io::posix::stream_descriptor> Base;

    public:
      typedef RCPtr<Tun> Ptr;

      Tun(openvpn_io::io_context& io_context,
	  ReadHandler read_handler_arg,
	  const Frame::Ptr& frame_arg,
	  const SessionStats::Ptr& stats_arg,
	  const std::string& name,
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
	ifr.ifr_flags |= IFF_NO_PI;
	if (layer() == Layer::OSI_LAYER_3)
	  ifr.ifr_flags |= IFF_TUN;
	else if (layer() == Layer::OSI_LAYER_2)
	  ifr.ifr_flags |= IFF_TAP;
	else
	  throw tun_layer_error("unknown OSI layer");

	open_unit(name, ifr, fd);

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
	Base::stream = new openvpn_io::posix::stream_descriptor(io_context, fd.release());
	OPENVPN_LOG_TUN(Base::name_ << " opened");
      }

      ~Tun() { Base::stop(); }

    private:
      static void open_unit(const std::string& name, struct ifreq& ifr, ScopedFD& fd)
      {
	if (!name.empty())
	  {
	    const int max_units = 256;
	    for (int unit = 0; unit < max_units; ++unit)
	      {
		std::string n = name;
		if (unit)
		  n += openvpn::to_string(unit);
		if (n.length() < IFNAMSIZ)
		  ::strcpy (ifr.ifr_name, n.c_str());
		else
		  throw tun_name_error();
		if (ioctl (fd(), TUNSETIFF, (void *) &ifr) == 0)
		  return;
	      }
	    const int eno = errno;
	    OPENVPN_THROW(tun_ioctl_error, "failed to open tun device '" << name << "' after trying " << max_units << " units : " << errinfo(eno));
	  }
	else
	  {
	    if (ioctl (fd(), TUNSETIFF, (void *) &ifr) < 0)
	      {
		const int eno = errno;
		OPENVPN_THROW(tun_ioctl_error, "failed to open tun device '" << name << "' : " << errinfo(eno));
	      }
	  }
      }
    };

  }
} // namespace openvpn

#endif // OPENVPN_TUN_LINUX_TUN_H
