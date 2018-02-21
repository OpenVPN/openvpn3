//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Inc.
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

// Client tun interface for Linux.

#ifndef OPENVPN_TUN_LINUX_CLIENT_TUNCLI_H
#define OPENVPN_TUN_LINUX_CLIENT_TUNCLI_H

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <openvpn/asio/asioerr.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/to_string.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/addr/route.hpp>
#include <openvpn/tun/tunio.hpp>
#include <openvpn/tun/builder/capture.hpp>
#include <openvpn/tun/linux/client/tunsetup.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>

namespace openvpn {
  namespace TunLinux {

    // exceptions
    OPENVPN_EXCEPTION(tun_open_error);
    OPENVPN_EXCEPTION(tun_layer_error);
    OPENVPN_EXCEPTION(tun_ioctl_error);
    OPENVPN_EXCEPTION(tun_fcntl_error);
    OPENVPN_EXCEPTION(tun_name_error);
    OPENVPN_EXCEPTION(tun_tx_queue_len_error);
    OPENVPN_EXCEPTION(tun_ifconfig_error);

    struct PacketFrom
    {
      typedef std::unique_ptr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

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

    class ClientConfig : public TunClientFactory
    {
    public:
      typedef RCPtr<ClientConfig> Ptr;

      std::string dev_name;
      int txqueuelen = 200;

      TunProp::Config tun_prop;

      int n_parallel = 8;
      Frame::Ptr frame;
      SessionStats::Ptr stats;

      void load(const OptionList& opt)
      {
	// set a default MTU
	if (!tun_prop.mtu)
	  tun_prop.mtu = 1500;

	// parse "dev" option
	if (dev_name.empty())
	  {
	    const Option* dev = opt.get_ptr("dev");
	    if (dev)
	      dev_name = dev->get(1, 64);
	  }
      }

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_tun_client_obj(openvpn_io::io_context& io_context,
						TunClientParent& parent,
						TransportClient* transcli);
    private:
      ClientConfig() {}
    };

    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor
      friend class TunIO<Client*, PacketFrom, openvpn_io::posix::stream_descriptor>;  // calls tun_read_handler

      typedef Tun<Client*> TunImpl;

    public:
      virtual void tun_start(const OptionList& opt, TransportClient& transcli, CryptoDCSettings&)
      {
	if (!impl)
	  {
	    halt = false;
	    try {
	      const IP::Addr server_addr = transcli.server_endpoint_addr();

	      // notify parent
	      parent.tun_pre_tun_config();

	      // parse pushed options
	      TunBuilderCapture::Ptr po(new TunBuilderCapture());
	      TunProp::configure_builder(po.get(),
					 state.get(),
					 config->stats.get(),
					 server_addr,
					 config->tun_prop,
					 opt,
					 nullptr,
					 false);

	      OPENVPN_LOG("CAPTURED OPTIONS:" << std::endl << po->to_string());

	      // configure tun/tap interface properties
	      ActionList::Ptr add_cmds = new ActionList();
	      remove_cmds.reset(new ActionList());

	      // start tun
	      impl.reset(new TunImpl(io_context,
				     this,
				     config->frame,
				     config->stats,
				     config->dev_name,
				     config->tun_prop.layer,
				     config->txqueuelen
				     ));
	      impl->start(config->n_parallel);

	      // get the iface name
	      state->iface_name = impl->name();

	      // configure tun properties
	      TunLinux::tun_config(state->iface_name, *po, nullptr, *add_cmds, *remove_cmds);

	      // execute commands to bring up interface
	      add_cmds->execute(std::cout);

	      // signal that we are connected
	      parent.tun_connected();
	    }
	    catch (const std::exception& e)
	      {
		stop();
		parent.tun_error(Error::TUN_SETUP_FAILED, e.what());
	      }
	  }
      }

      virtual bool tun_send(BufferAllocated& buf)
      {
	return send(buf);
      }

      virtual std::string tun_name() const
      {
	if (impl)
	  return impl->name();
	else
	  return "UNDEF_TUN";
      }

      virtual std::string vpn_ip4() const
      {
	if (state->vpn_ip4_addr.specified())
	  return state->vpn_ip4_addr.to_string();
	else
	  return "";
      }

      virtual std::string vpn_ip6() const
      {
	if (state->vpn_ip6_addr.specified())
	  return state->vpn_ip6_addr.to_string();
	else
	  return "";
      }

      virtual std::string vpn_gw4() const override
      {
	if (state->vpn_ip4_gw.specified())
	  return state->vpn_ip4_gw.to_string();
	else
	  return "";
      }

      virtual std::string vpn_gw6() const override
      {
	if (state->vpn_ip6_gw.specified())
	  return state->vpn_ip6_gw.to_string();
	else
	  return "";
      }

      virtual void set_disconnect()
      {
      }

      virtual void stop() { stop_(); }
      virtual ~Client() { stop_(); }

    private:
      Client(openvpn_io::io_context& io_context_arg,
	     ClientConfig* config_arg,
	     TunClientParent& parent_arg)
	:  io_context(io_context_arg),
	   config(config_arg),
	   parent(parent_arg),
	   state(new TunProp::State()),
	   halt(false)
      {
      }

      bool send(Buffer& buf)
      {
	if (impl)
	  return impl->write(buf);
	else
	  return false;
      }

      void tun_read_handler(PacketFrom::SPtr& pfp) // called by TunImpl
      {
	parent.tun_recv(pfp->buf);
      }

      void tun_error_handler(const Error::Type errtype, // called by TunImpl
			     const openvpn_io::error_code* error)
      {
      }

      void stop_()
      {
	if (!halt)
	  {
	    halt = true;

	    // remove added routes
	    if (remove_cmds)
	      remove_cmds->execute(std::cout);

	    // stop tun
	    if (impl)
	      impl->stop();
	  }
      }

      openvpn_io::io_context& io_context;
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunImpl::Ptr impl;
      TunProp::State::Ptr state;
      ActionList::Ptr remove_cmds;
      bool halt;
    };

    inline TunClient::Ptr ClientConfig::new_tun_client_obj(openvpn_io::io_context& io_context,
							   TunClientParent& parent,
							   TransportClient* transcli)
    {
      return TunClient::Ptr(new Client(io_context, this, parent));
    }

  }
} // namespace openvpn

#endif // OPENVPN_TUN_LINUX_CLIENT_TUNCLI_H
