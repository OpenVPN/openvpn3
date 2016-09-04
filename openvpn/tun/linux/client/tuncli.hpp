//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
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

#include <openvpn/common/exception.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/format.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/addr/route.hpp>
#include <openvpn/tun/builder/capture.hpp>
#include <openvpn/tun/linux/tun.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>

namespace openvpn {
  namespace TunLinux {

    OPENVPN_EXCEPTION(tun_linux_error);

    enum { // add_del_route flags
      R_IPv6=(1<<0),
      R_ADD_SYS=(1<<1),
      R_ADD_DCO=(1<<2),
      R_ADD_ALL=R_ADD_SYS|R_ADD_DCO,
    };

    inline IP::Addr cvt_pnr_ip_v4(const std::string& hexaddr)
    {
      BufferAllocated v(4, BufferAllocated::CONSTRUCT_ZERO);
      parse_hex(v, hexaddr);
      if (v.size() != 4)
	throw tun_linux_error("bad hex address");
      IPv4::Addr ret = IPv4::Addr::from_bytes(v.data());
      return IP::Addr::from_ipv4(ret);
    }

    inline IP::Addr get_default_gateway_v4()
    {
      typedef std::vector<std::string> strvec;
      const std::string proc_net_route = read_text_simple("/proc/net/route");
      SplitLines in(proc_net_route, 0);
      while (in(true))
	{
	  const std::string& line = in.line_ref();
	  strvec v = Split::by_space<strvec, StandardLex, SpaceMatch, Split::NullLimit>(line);
	  if (v.size() >= 8)
	    {
	      if (v[1] == "00000000" && v[7] == "00000000")
		{
		  const IP::Addr gw = cvt_pnr_ip_v4(v[2]);
		  return gw;
		}
	    }
	}
      throw tun_linux_error("can't determine default gateway");
    }

    inline void add_del_route(const std::string& addr_str,
			      const int prefix_len,
			      const std::string& gateway_str,
			      const unsigned int flags,
			      std::vector<IP::Route>* rtvec,
			      Action::Ptr& create,
			      Action::Ptr& destroy)
    {
      if (flags & R_IPv6)
	{
	  const IPv6::Addr addr = IPv6::Addr::from_string(addr_str);
	  const IPv6::Addr netmask = IPv6::Addr::netmask_from_prefix_len(prefix_len);
	  const IPv6::Addr net = addr & netmask;

	  if (flags & R_ADD_SYS)
	    {
	      // ip route add 2001:db8:1::/48 via 2001:db8:1::1
	      Command::Ptr add(new Command);
	      add->argv.push_back("/sbin/ip");
	      add->argv.push_back("-6");
	      add->argv.push_back("route");
	      add->argv.push_back("add");
	      add->argv.push_back(net.to_string() + '/' + openvpn::to_string(prefix_len));
	      add->argv.push_back("via");
	      add->argv.push_back(gateway_str);
	      create = add;

	      // for the destroy command, copy the add command but replace "add" with "delete"
	      Command::Ptr del(add->copy());
	      del->argv[3] = "del";
	      destroy = del;
	    }

	  if (rtvec && (flags & R_ADD_DCO))
	    rtvec->emplace_back(IP::Addr::from_ipv6(net), prefix_len);
	}
      else
	{
	  const IPv4::Addr addr = IPv4::Addr::from_string(addr_str);
	  const IPv4::Addr netmask = IPv4::Addr::netmask_from_prefix_len(prefix_len);
	  const IPv4::Addr net = addr & netmask;

	  if (flags & R_ADD_SYS)
	    {
	      // ip route add 192.0.2.128/25 via 192.0.2.1
	      Command::Ptr add(new Command);
	      add->argv.push_back("/sbin/ip");
	      add->argv.push_back("-4");
	      add->argv.push_back("route");
	      add->argv.push_back("add");
	      add->argv.push_back(net.to_string() + '/' + openvpn::to_string(prefix_len));
	      add->argv.push_back("via");
	      add->argv.push_back(gateway_str);
	      create = add;

	      // for the destroy command, copy the add command but replace "add" with "delete"
	      Command::Ptr del(add->copy());
	      del->argv[3] = "del";
	      destroy = del;
	    }

	  if (rtvec && (flags & R_ADD_DCO))
	    rtvec->emplace_back(IP::Addr::from_ipv4(net), prefix_len);
	}
    }

    inline void add_del_route(const std::string& addr_str,
			      const int prefix_len,
			      const std::string& gateway_str,
			      const unsigned int flags,
			      std::vector<IP::Route>* rtvec,
			      ActionList& create,
			      ActionList& destroy)
    {
      Action::Ptr c, d;
      add_del_route(addr_str, prefix_len, gateway_str, flags, rtvec, c, d);
      create.add(c);
      destroy.add(d);
    }

    inline void iface_up(const std::string& iface_name,
			     const int mtu,
			     ActionList& create,
			     ActionList& destroy)
    {
      {
	Command::Ptr add(new Command);
	add->argv.push_back("/sbin/ip");
	add->argv.push_back("link");
	add->argv.push_back("set");
	add->argv.push_back(iface_name);
	add->argv.push_back("up");
	if (mtu > 0)
	  {
	    add->argv.push_back("mtu");
	    add->argv.push_back(openvpn::to_string(mtu));
	  }
	create.add(add);

	// for the destroy command, copy the add command but replace "up" with "down"
	Command::Ptr del(add->copy());
	del->argv[4] = "down";
	destroy.add(del);
      }
    }

    inline void iface_config(const std::string& iface_name,
			     int unit,
			     const TunBuilderCapture& pull,
			     std::vector<IP::Route>* rtvec,
			     ActionList& create,
			     ActionList& destroy)
    {
      // set local4 and local6 to point to IPv4/6 route configurations
      const TunBuilderCapture::RouteAddress* local4 = pull.vpn_ipv4();
      const TunBuilderCapture::RouteAddress* local6 = pull.vpn_ipv6();

      // Set IPv4 Interface
      if (local4)
	{
	  Command::Ptr add(new Command);
	  add->argv.push_back("/sbin/ip");
	  add->argv.push_back("-4");
	  add->argv.push_back("addr");
	  add->argv.push_back("add");
	  add->argv.push_back(local4->address + '/' + openvpn::to_string(local4->prefix_length));
	  add->argv.push_back("broadcast");
	  add->argv.push_back((IPv4::Addr::from_string(local4->address) | ~IPv4::Addr::netmask_from_prefix_len(local4->prefix_length)).to_string());
	  add->argv.push_back("dev");
	  add->argv.push_back(iface_name);
	  if (unit >= 0)
	    {
	      add->argv.push_back("label");
	      add->argv.push_back(iface_name + ':' + openvpn::to_string(unit));
	    }
	  create.add(add);

	  // for the destroy command, copy the add command but replace "add" with "delete"
	  Command::Ptr del(add->copy());
	  del->argv[3] = "del";
	  destroy.add(del);

	  // add interface route to rtvec if defined
	  add_del_route(local4->address, local4->prefix_length, local4->address, R_ADD_DCO, rtvec, create, destroy);
	}

      // Set IPv6 Interface
      if (local6 && !pull.block_ipv6)
	{
	  Command::Ptr add(new Command);
	  add->argv.push_back("/sbin/ip");
	  add->argv.push_back("-6");
	  add->argv.push_back("addr");
	  add->argv.push_back("add");
	  add->argv.push_back(local6->address + '/' + openvpn::to_string(local6->prefix_length));
	  add->argv.push_back("dev");
	  add->argv.push_back(iface_name);
	  create.add(add);

	  // for the destroy command, copy the add command but replace "add" with "delete"
	  Command::Ptr del(add->copy());
	  del->argv[3] = "del";
	  destroy.add(del);

	  // add interface route to rtvec if defined
	  add_del_route(local6->address, local6->prefix_length, local6->address, R_ADD_DCO|R_IPv6, rtvec, create, destroy);
	}
    }

    inline void tun_config(const std::string& iface_name,
			   const TunBuilderCapture& pull,
			   std::vector<IP::Route>* rtvec,
			   ActionList& create,
			   ActionList& destroy)
    {
      const IP::Addr gw4 = get_default_gateway_v4();

      // set local4 and local6 to point to IPv4/6 route configurations
      const TunBuilderCapture::RouteAddress* local4 = pull.vpn_ipv4();
      const TunBuilderCapture::RouteAddress* local6 = pull.vpn_ipv6();

      // configure interface
      iface_up(iface_name, pull.mtu, create, destroy);
      iface_config(iface_name, -1, pull, rtvec, create, destroy);

      // Process Routes
      {
	for (const auto &route : pull.add_routes)
	  {
	    if (route.ipv6)
	      {
		if (!pull.block_ipv6)
		  add_del_route(route.address, route.prefix_length, local6->gateway, R_ADD_ALL|R_IPv6, rtvec, create, destroy);
	      }
	    else
	      {
		if (local4 && !local4->gateway.empty())
		  add_del_route(route.address, route.prefix_length, local4->gateway, R_ADD_ALL, rtvec, create, destroy);
		else
		  OPENVPN_LOG("ERROR: IPv4 route pushed without IPv4 ifconfig and/or route-gateway");
	      }
	  }
      }

      // Process exclude routes
      {
	for (const auto &route : pull.exclude_routes)
	  {
	    if (route.ipv6)
	      {
		OPENVPN_LOG("NOTE: exclude IPv6 routes not supported yet"); // fixme
	      }
	    else
	      {
		if (gw4.defined())
		  add_del_route(route.address, route.prefix_length, gw4.to_string(), R_ADD_SYS, rtvec, create, destroy);
		else
		  OPENVPN_LOG("NOTE: cannot determine gateway for exclude IPv4 routes");
	      }
	  }
      }

      // Process IPv4 redirect-gateway
      if (pull.reroute_gw.ipv4)
	{
	  // add bypass route
	  if (!pull.remote_address.ipv6 && !(pull.reroute_gw.flags & RedirectGatewayFlags::RG_LOCAL))
	    add_del_route(pull.remote_address.address, 32, gw4.to_string(), R_ADD_SYS, rtvec, create, destroy);

	  add_del_route("0.0.0.0", 1, local4->gateway, R_ADD_ALL, rtvec, create, destroy);
	  add_del_route("128.0.0.0", 1, local4->gateway, R_ADD_ALL, rtvec, create, destroy);
	}

      // Process IPv6 redirect-gateway
      if (pull.reroute_gw.ipv6 && !pull.block_ipv6)
	{
	  add_del_route("0000::", 1, local6->gateway, R_ADD_ALL|R_IPv6, rtvec, create, destroy);
	  add_del_route("8000::", 1, local6->gateway, R_ADD_ALL|R_IPv6, rtvec, create, destroy);
	}

      // fixme -- Process block-ipv6

      // fixme -- Handle pushed DNS servers
    }

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

      virtual TunClient::Ptr new_tun_client_obj(asio::io_context& io_context,
						TunClientParent& parent,
						TransportClient* transcli);
    private:
      ClientConfig() {}
    };

    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor
      friend class TunIO<Client*, PacketFrom, asio::posix::stream_descriptor>;  // calls tun_read_handler

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
      Client(asio::io_context& io_context_arg,
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
			     const asio::error_code* error)
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

      asio::io_context& io_context;
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunImpl::Ptr impl;
      TunProp::State::Ptr state;
      ActionList::Ptr remove_cmds;
      bool halt;
    };

    inline TunClient::Ptr ClientConfig::new_tun_client_obj(asio::io_context& io_context,
							   TunClientParent& parent,
							   TransportClient* transcli)
    {
      return TunClient::Ptr(new Client(io_context, this, parent));
    }

  }
} // namespace openvpn

#endif // OPENVPN_TUN_LINUX_CLIENT_TUNCLI_H
