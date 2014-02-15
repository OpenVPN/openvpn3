//
//  tun.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Low-level tun interface driver for Mac OS X, client/server independent.

#ifndef OPENVPN_TUN_MAC_TUN_H
#define OPENVPN_TUN_MAC_TUN_H

#include <fcntl.h>
#include <errno.h>

#include <string>
#include <sstream>

#include <openvpn/common/process.hpp>
#include <openvpn/common/format.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/tun/tunio.hpp>

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
    class Tun : public TunIO<ReadHandler, PacketFrom, boost::asio::posix::stream_descriptor>
    {
      typedef TunIO<ReadHandler, PacketFrom, boost::asio::posix::stream_descriptor> Base;

    public:
      typedef boost::intrusive_ptr<Tun> Ptr;

      Tun(boost::asio::io_service& io_service,
	  ReadHandler read_handler_arg,
	  const Frame::Ptr& frame_arg,
	  const SessionStats::Ptr& stats_arg,
	  const Layer& layer)
	: Base(read_handler_arg, frame_arg, stats_arg)
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

		Base::name_ = node_str;
		Base::stream = new boost::asio::posix::stream_descriptor(io_service, fd.release());
		OPENVPN_LOG_TUN(node_fn << " opened");
		return;
	      }
	  }

	OPENVPN_THROW(tun_open_error, "error opening Mac " << layer.dev_type() << " device");
      }

      std::string ifconfig(const OptionList& opt, const unsigned int mtu) // fixme -- support IPv6
      {
	// first verify topology
	{
	  const Option& o = opt.get("topology");
	  o.min_args(2);
	  if (o.ref(1) != "subnet")
	    throw option_error("only topology subnet supported");
	}

	// configure tun interface
	{
	  int status;
	  const Option& o = opt.get("ifconfig");
	  o.exact_args(3);
	  const IP::Addr ip = IP::Addr::from_string(o.get(1, 256), "ifconfig-ip");
	  const IP::Addr mask = IP::Addr::from_string(o.get(2, 256), "ifconfig-net");
	  {
	    Argv argv;
	    argv.push_back("/sbin/ifconfig");
	    argv.push_back(Base::name());
	    argv.push_back(ip.to_string());
	    argv.push_back(ip.to_string());
	    argv.push_back("netmask");
	    argv.push_back(mask.to_string());
	    argv.push_back("mtu");
	    argv.push_back(to_string(mtu));
	    argv.push_back("up");
	    OPENVPN_LOG_TUN(argv.to_string());
	    status = system_cmd(argv[0], argv);
	  }
	  if (!status)
	    {
	    Argv argv;
	      const IP::Addr net = ip & mask;
	      argv.push_back("/sbin/route");
	      argv.push_back("add");
	      argv.push_back("-net");
	      argv.push_back(net.to_string());
	      argv.push_back(ip.to_string());
	      argv.push_back(mask.to_string());
	      OPENVPN_LOG_TUN(argv.to_string());
	      status = system_cmd(argv[0], argv);
	    }
	  if (status)
	    throw tun_ifconfig_error();
	  return ip.to_string();
	}
      }

      ~Tun() { Base::stop(); }
    };

  }
} // namespace openvpn

#endif // OPENVPN_TUN_MAC_TUN_H
