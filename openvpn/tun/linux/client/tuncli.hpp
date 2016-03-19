//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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
      R_ADD_ALL=(1<<1),
      R_ADD_DCO=(1<<2),
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
			      std::vector<IP::Route>& rtvec,
			      Action::Ptr& create,
			      Action::Ptr& destroy)
    {
      if (flags & R_IPv6)
	{
	  OPENVPN_LOG("NOTE: route IPv6 not implemented yet"); // fixme
	}
      else
	{
	  const IPv4::Addr addr = IPv4::Addr::from_string(addr_str);
	  const IPv4::Addr netmask = IPv4::Addr::netmask_from_prefix_len(prefix_len);
	  const IPv4::Addr net = addr & netmask;

	  if (flags & R_ADD_ALL)
	    {
	      Command::Ptr add(new Command);
	      add->argv.push_back("/sbin/route");
	      add->argv.push_back("add");
	      add->argv.push_back("-net");
	      add->argv.push_back(net.to_string());
	      add->argv.push_back("netmask");
	      add->argv.push_back(netmask.to_string());
	      add->argv.push_back("gw");
	      add->argv.push_back(gateway_str);
	      create = add;

	      // for the destroy command, copy the add command but replace "add" with "delete"
	      Command::Ptr del(add->copy());
	      del->argv[1] = "del";
	      destroy = del;
	    }

	  if (flags & (R_ADD_ALL|R_ADD_DCO))
	    rtvec.emplace_back(IP::Addr::from_ipv4(net), prefix_len);
	}
    }

    inline void add_del_route(const std::string& addr_str,
			      const int prefix_len,
			      const std::string& gateway_str,
			      const unsigned int flags,
			      std::vector<IP::Route>& rtvec,
			      ActionList& create,
			      ActionList& destroy)
    {
      Action::Ptr c, d;
      add_del_route(addr_str, prefix_len, gateway_str, flags, rtvec, c, d);
      create.add(c);
      destroy.add(d);
    }

    inline void tun_config(const std::string& iface_name,
			   const TunBuilderCapture& pull,
			   std::vector<IP::Route>& rtvec,
			   const bool enable_routes,
			   ActionList& create,
			   ActionList& destroy)
    {
      // set local4 and local6 to point to IPv4/6 route configurations
      const TunBuilderCapture::RouteAddress* local4 = pull.vpn_ipv4();
      const TunBuilderCapture::RouteAddress* local6 = pull.vpn_ipv6();

      // Set IPv4 Interface
      if (local4)
	{
	  const IPv4::Addr netmask = IPv4::Addr::netmask_from_prefix_len(local4->prefix_length);
	  Command::Ptr cmd(new Command);
	  cmd->argv.push_back("/sbin/ifconfig");
	  cmd->argv.push_back(iface_name);
	  cmd->argv.push_back(local4->address);
	  cmd->argv.push_back("netmask");
	  cmd->argv.push_back(netmask.to_string());
	  cmd->argv.push_back("mtu");
	  cmd->argv.push_back(to_string(pull.mtu));
	  create.add(cmd);

	  add_del_route(local4->address, local4->prefix_length, local4->address, R_ADD_DCO, rtvec, create, destroy);
	}

      if (local6)
	OPENVPN_LOG("NOTE: ifconfig IPv6 not implemented yet"); // fixme

      if (enable_routes)
	{
	  // Process Routes
	  {
	    for (auto i = pull.add_routes.begin(); i != pull.add_routes.end(); ++i)
	      {
		const TunBuilderCapture::Route& route = *i;
		if (route.ipv6)
		  add_del_route(route.address, route.prefix_length, local6->gateway, R_ADD_ALL|R_IPv6, rtvec, create, destroy);
		else
		  {
		    if (local4 && !local4->gateway.empty())
		      add_del_route(route.address, route.prefix_length, local4->gateway, R_ADD_ALL, rtvec, create, destroy);
		    else
		      OPENVPN_LOG("ERROR: IPv4 route pushed without IPv4 ifconfig and/or route-gateway");
		  }
	      }
	  }

	  // Process IPv4 redirect-gateway
	  if (pull.reroute_gw.ipv4)
	    {
	      if (!pull.remote_address.ipv6 && !(pull.reroute_gw.flags & RedirectGatewayFlags::RG_LOCAL))
		add_del_route(pull.remote_address.address, 32, get_default_gateway_v4().to_string(), R_ADD_ALL, rtvec, create, destroy);

	      add_del_route("0.0.0.0", 1, local4->gateway, R_ADD_ALL, rtvec, create, destroy);
	      add_del_route("128.0.0.0", 1, local4->gateway, R_ADD_ALL, rtvec, create, destroy);
	    }
	}

      // fixme -- handled pushed DNS servers
    }

    class ClientConfig : public TunClientFactory
    {
    public:
      typedef RCPtr<ClientConfig> Ptr;

      std::string dev_name;
      Layer layer;
      int txqueuelen;

      TunProp::Config tun_prop;

      int n_parallel;
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

	// no trunking support yet
	if (opt.exists("trunk-table"))
	  throw option_error("no trunking support");
      }

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_tun_client_obj(asio::io_context& io_context,
						TunClientParent& parent,
						TransportClient* transcli);
    private:
      ClientConfig()
	: txqueuelen(200), n_parallel(8) {}
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
				     config->layer,
				     config->txqueuelen
				     ));
	      impl->start(config->n_parallel);

	      // get the iface name
	      state->iface_name = impl->name();

	      // configure tun properties
	      std::vector<IP::Route> rtvec;
	      TunLinux::tun_config(state->iface_name, *po, rtvec, true, *add_cmds, *remove_cmds);

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
