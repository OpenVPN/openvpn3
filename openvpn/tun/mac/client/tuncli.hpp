//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

// Client tun interface for Mac OS X

#ifndef OPENVPN_TUN_MAC_CLIENT_TUNCLI_H
#define OPENVPN_TUN_MAC_CLIENT_TUNCLI_H

#include <string>
#include <sstream>

#include <openvpn/common/format.hpp>
#include <openvpn/common/scoped_asio_stream.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/tun/persist/tunwrap.hpp>
#include <openvpn/tun/persist/tunwrapasio.hpp>
#include <openvpn/tun/tunio.hpp>
#include <openvpn/tun/layer.hpp>
#include <openvpn/tun/mac/tunutil.hpp>
#include <openvpn/tun/mac/utun.hpp>
#include <openvpn/tun/mac/macgw.hpp>
#include <openvpn/tun/mac/macdns_watchdog.hpp>

namespace openvpn {
  namespace TunMac {

    OPENVPN_EXCEPTION(tun_mac_error);

    enum { // add_del_route flags
      R_IPv6=(1<<0),
      R_IFACE=(1<<1),
      R_IFACE_HINT=(1<<2),
      R_ONLINK=(1<<3),
      R_REJECT=(1<<4),
      R_BLACKHOLE=(1<<5),
    };

    inline void add_del_route(const std::string& addr_str,
			      const int prefix_len,
			      const std::string& gateway_str,
			      const std::string& iface,
			      const unsigned int flags,
			      Action::Ptr& create,
			      Action::Ptr& destroy)
    {
      if (flags & R_IPv6)
	{
	  const IPv6::Addr addr = IPv6::Addr::from_string(addr_str);
	  const IPv6::Addr netmask = IPv6::Addr::netmask_from_prefix_len(prefix_len);
	  const IPv6::Addr net = addr & netmask;

	  Command::Ptr add(new Command);
	  add->argv.push_back("/sbin/route");
	  add->argv.push_back("add");
	  add->argv.push_back("-net");
	  add->argv.push_back("-inet6");
	  add->argv.push_back(net.to_string());
	  add->argv.push_back("-prefixlen");
	  add->argv.push_back(to_string(prefix_len));
	  if (flags & R_REJECT)
	    add->argv.push_back("-reject");
	  if (flags & R_BLACKHOLE)
	    add->argv.push_back("-blackhole");
	  if (!iface.empty())
	    {
	      if (flags & R_IFACE)
		{
		  add->argv.push_back("-iface");
		  add->argv.push_back(iface);
		}
	    }
	  if (!gateway_str.empty() && !(flags & R_IFACE))
	    {
	      std::string g = gateway_str;
	      if (flags & R_IFACE_HINT)
		g += '%' + iface;
	      add->argv.push_back(g);
	    }
	  create = add;

	  // for the destroy command, copy the add command but replace "add" with "delete"
	  Command::Ptr del(add->copy());
	  del->argv[1] = "delete";
	  destroy = del;
	}
      else
	{
	  const IPv4::Addr addr = IPv4::Addr::from_string(addr_str);
	  const IPv4::Addr netmask = IPv4::Addr::netmask_from_prefix_len(prefix_len);
	  const IPv4::Addr net = addr & netmask;

	  Command::Ptr add(new Command);
	  add->argv.push_back("/sbin/route");
	  add->argv.push_back("add");
	  if (flags & R_ONLINK)
	    {
	      add->argv.push_back("-cloning");
	      add->argv.push_back("-net");
	      add->argv.push_back(net.to_string());
	      add->argv.push_back("-netmask");
	      add->argv.push_back(netmask.to_string());
	      add->argv.push_back("-interface");
	      add->argv.push_back(iface);
	    }
	  else
	    {
	      add->argv.push_back("-net");
	      add->argv.push_back(net.to_string());
	      add->argv.push_back("-netmask");
	      add->argv.push_back(netmask.to_string());
	      if (flags & R_REJECT)
		add->argv.push_back("-reject");
	      if (flags & R_BLACKHOLE)
		add->argv.push_back("-blackhole");
	      if (!iface.empty())
		{
		  if (flags & R_IFACE)
		    {
		      add->argv.push_back("-iface");
		      add->argv.push_back(iface);
		    }
		}
	      add->argv.push_back(gateway_str);
	    }
	  create = add;

	  // for the destroy command, copy the add command but replace "add" with "delete"
	  Command::Ptr del(add->copy());
	  del->argv[1] = "delete";
	  destroy = del;
	}
    }

    inline void add_del_route(const std::string& addr_str,
			      const int prefix_len,
			      const std::string& gateway_str,
			      const std::string& iface,
			      const unsigned int flags,
			      ActionList& create,
			      ActionList& destroy)
    {
      Action::Ptr c, d;
      add_del_route(addr_str, prefix_len, gateway_str, iface, flags, c, d);
      create.add(c);
      destroy.add(d);
    }

    // struct used to pass received tun packets
    struct PacketFrom
    {
      typedef ScopedPtr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    // tun interface wrapper for Mac OS X
    template <typename ReadHandler, typename TunWrap>
    class Tun : public TunIO<ReadHandler, PacketFrom, TunWrapAsioStream<TunWrap> >
    {
      typedef TunIO<ReadHandler, PacketFrom, TunWrapAsioStream<TunWrap>  > Base;

    public:
      typedef boost::intrusive_ptr<Tun> Ptr;

      Tun(const typename TunWrap::Ptr& tun_wrap,
	  const std::string& name,
	  const bool retain_stream,
	  const bool tun_prefix,
	  ReadHandler read_handler,
	  const Frame::Ptr& frame,
	  const SessionStats::Ptr& stats)
	: Base(read_handler, frame, stats)
      {
	Base::name_ = name;
	Base::retain_stream = retain_stream;
	Base::tun_prefix = tun_prefix;
	Base::stream = new TunWrapAsioStream<TunWrap>(tun_wrap);
      }
    };

    // These types manage the underlying tun driver fd
    typedef boost::asio::posix::stream_descriptor TUNStream;
    typedef ScopedAsioStream<TUNStream> ScopedTUNStream;
    typedef TunWrapTemplate<ScopedTUNStream> TunWrap;

    // Failsafe blocker.  Try to prevent leakage of unencrypted data
    // to internet during pause/reconnect states.
    class FailsafeBlock : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<FailsafeBlock> Ptr;

      FailsafeBlock()
	: halt(false),
	  block_v4(false),
	  block_v6(false),
	  block_v6_public(false)
      {
      }

      ~FailsafeBlock()
      {
	finalize(true);
      }

      const bool ip_hole_punch_exists(const Action::Ptr& action)
      {
	if (ip_hole_punch_added)
	  return ip_hole_punch_added->exists(action);
	else
	  return false;
      }

      void init()
      {
	block_v4 = false;
	block_v6 = false;
	dns.reset();
      }

      void add_dns(const MacDNS::Config::Ptr& dns_arg)
      {
	dns = dns_arg;
      }

      void add_block_v4()
      {
	block_v4 = true;
      }

      void add_block_v6()
      {
	block_v6 = true;
      }

      void add_block_v6_public()
      {
	block_v6_public = true;
      }

      void ip_hole_punch(const IP::Addr& addr)
      {
	if (!halt && (((addr.version() == IP::Addr::V4) && block_v4_teardown)
		   || ((addr.version() == IP::Addr::V6) && block_v6_teardown)))
	  {
	    if (!ip_hole_punch_added)
	      ip_hole_punch_added.reset(new ActionList);
	    if (!ip_hole_punch_teardown)
	      ip_hole_punch_teardown.reset(new ActionList);

	    Action::Ptr create, destroy;
	    MacGWInfo gw;
	    if (addr.version() == IP::Addr::V4)
	      {
		if (gw.v4.defined())
		  add_del_route(addr.to_string(), 32, gw.v4.router.to_string(), gw.v4.iface, 0, create, destroy);
		else
		  OPENVPN_LOG("FailsafeBlock::ip_hole_punch: IPv4 gateway undefined");
	      }
	    else if (addr.version() == IP::Addr::V6)
	      {
		if (gw.v6.defined())
		  add_del_route(addr.to_string(), 128, gw.v6.router.to_string(), gw.v6.iface, R_IPv6|R_IFACE_HINT, create, destroy);
		else
		  OPENVPN_LOG("FailsafeBlock::ip_hole_punch: IPv6 gateway undefined");
	      }

	    if (!ip_hole_punch_added->exists(create))
	      {
		ip_hole_punch_added->add(create);
		ip_hole_punch_teardown->add(destroy);

		ActionList::Ptr add_cmds = new ActionList();
		add_cmds->add(create);
		add_cmds->execute();
	      }
	  }
      }

      void establish(ActionList& create, ActionList& destroy)
      {
	if (!halt)
	  {
	    // block IPv4
	    if (block_v4 && !block_v4_teardown)
	      {
		block_v4_teardown.reset(new ActionList);
		add_del_route("0.0.0.0", 1, "127.0.0.1", "lo0", R_BLACKHOLE, create, *block_v4_teardown);
		add_del_route("128.0.0.0", 1, "127.0.0.1", "lo0", R_BLACKHOLE, create, *block_v4_teardown);
	      }
	    else if (!block_v4 && block_v4_teardown)
	      {
		create.add(*block_v4_teardown);
		block_v4_teardown.reset();
	      }

	    // block IPv6
	    if ((block_v6 || block_v6_public) && !block_v6_teardown)
	      {
		block_v6_teardown.reset(new ActionList);
		if (block_v6_public)
		  {
		    add_del_route("2000::", 4, "::1", "lo0", R_IPv6|R_REJECT|R_IFACE_HINT, create, *block_v6_teardown);
		    add_del_route("3000::", 4, "::1", "lo0", R_IPv6|R_REJECT|R_IFACE_HINT, create, *block_v6_teardown);
		    add_del_route("fc00::", 7, "::1", "lo0", R_IPv6|R_REJECT|R_IFACE_HINT, create, *block_v6_teardown);
		  }
		else
		  {
#if 0 // fixme -- strangely, this code blocks ALL subsequently added routes, even with higher prefix lengths!
		    add_del_route("0000::", 1, "::1", "lo0", R_IPv6|R_BLACKHOLE|R_IFACE_HINT, create, *block_v6_teardown);
		    add_del_route("8000::", 1, "::1", "lo0", R_IPv6|R_BLACKHOLE|R_IFACE_HINT, create, *block_v6_teardown);
#endif
		  }
	      }
	    else if (!(block_v6 || block_v6_public) && block_v6_teardown)
	      {
		create.add(*block_v6_teardown);
		block_v6_teardown.reset();
	      }

	    // IP hole punch
	    if (ip_hole_punch_teardown)
	      {
		destroy.add(*ip_hole_punch_teardown);
		ip_hole_punch_teardown.reset();
		ip_hole_punch_added.reset();
	      }

	    // DNS
	    if (dns || dns_watchdog)
	      {
		if (!dns_watchdog)
		  dns_watchdog.reset(new MacDNSWatchdog);
		MacDNSWatchdog::DNSAction::Ptr da(new MacDNSWatchdog::DNSAction(dns_watchdog, dns, MacDNSWatchdog::FLUSH_RECONFIG));
		create.add(da);
		teardown_dns = MacDNS::Config::block(dns.get());
	      }
	    else
	      teardown_dns.reset();
	  }
      }

      void finalize(const bool disconnected)
      {
	if (!halt)
	  {
	    halt = disconnected;
	    ActionList::Ptr cmds = new ActionList();

	    // IP hole punch
	    if (ip_hole_punch_teardown)
	      {
		cmds->add(*ip_hole_punch_teardown);
		ip_hole_punch_teardown.reset();
		ip_hole_punch_added.reset();
	      }

	    if (disconnected)
	      {
		// block IPv4
		if (block_v4_teardown)
		  {
		    cmds->add(*block_v4_teardown);
		    block_v4_teardown.reset();
		  }

		// block IPv6
		if (block_v6_teardown)
		  {
		    cmds->add(*block_v6_teardown);
		    block_v6_teardown.reset();
		  }

		// DNS
		teardown_dns.reset();
	      }

	    // DNS
	    if (dns_watchdog)
	      {
		MacDNSWatchdog::DNSAction::Ptr da(new MacDNSWatchdog::DNSAction(dns_watchdog,
										teardown_dns,
										teardown_dns ? 0 : MacDNSWatchdog::FLUSH_RECONFIG));
		cmds->add(da);
	      }

	    // execute commands
	    cmds->execute();
	  }
      }

    private:
      bool halt;

      bool block_v4;
      bool block_v6;
      bool block_v6_public;
      MacDNS::Config::Ptr dns;
      MacDNS::Config::Ptr teardown_dns;

      MacDNSWatchdog::Ptr dns_watchdog;
      ActionList::Ptr ip_hole_punch_added;
      ActionList::Ptr ip_hole_punch_teardown;
      ActionList::Ptr block_v4_teardown;
      ActionList::Ptr block_v6_teardown;
    };

    class Client;

    class ClientConfig : public TunClientFactory
    {
      friend class Client; // accesses fsblock

    public:
      typedef boost::intrusive_ptr<ClientConfig> Ptr;

      Layer layer;               // OSI layer

      TunProp::Config tun_prop;
      int n_parallel;            // number of parallel async reads on tun socket

      bool enable_failsafe_block;

      Frame::Ptr frame;
      SessionStats::Ptr stats;

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_client_obj(boost::asio::io_service& io_service,
					    TunClientParent& parent);

      // return true if layer 2 tunnels are supported
      virtual bool layer_2_supported() const
      {
#       if defined(MAC_TUNTAP_FALLBACK)
	  return false; // change to true after TAP support is added
#       else
	  return false; // utun device doesn't support TAP
#       endif
      }

      // called just prior to transmission of Disconnect event
      virtual void finalize(const bool disconnected)
      {
	if (fsblock)
	  fsblock->finalize(disconnected);
      }

      // Called just prior to transport layer opening up a socket to addr.
      // Allows the implementation to ensure connectivity for outgoing
      // transport connection to server.
      virtual void ip_hole_punch(const IP::Addr& addr)
      {
	if (fsblock)
	  fsblock->ip_hole_punch(addr);
      }

    private:
      ClientConfig() : n_parallel(8) {}

      FailsafeBlock::Ptr fsblock;
    };

    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor
      friend class TunIO<Client*, PacketFrom, TunWrapAsioStream<TunWrap> >;  // calls tun_read_handler

      typedef Tun<Client*, TunWrap> TunImpl;

    public:
      virtual void client_start(const OptionList& opt, TransportClient& transcli)
      {
	if (!impl)
	  {
	    halt = false;
	    tun_wrap.reset(new TunWrap(false));

	    try {
	      bool tun_prefix = false;
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
					 false);

	      // handle MTU default
	      if (!po->mtu)
		po->mtu = 1500;

	      OPENVPN_LOG("CAPTURED OPTIONS:" << std::endl << po->to_string()); // fixme

	      // Open tun device.  Try Mac OS X integrated utun device first
	      // (layer 3 only).  If utun fails and MAC_TUNTAP_FALLBACK is defined,
	      // then fall back to TunTap third-party device.
	      // If successful, state->iface_name will be set to tun iface name.
	      int fd = -1;
	      try {
#                   if defined(MAC_TUNTAP_FALLBACK)
#                     if !defined(BOOST_ASIO_DISABLE_KQUEUE)
#                       error Mac OS X TunTap adapter is incompatible with kqueue; rebuild with BOOST_ASIO_DISABLE_KQUEUE
#                     endif
		if (config->layer() == Layer::OSI_LAYER_3)
		  {
		    try {
		      fd = UTun::utun_open(state->iface_name);
		      tun_prefix = true;
		    }
		    catch (const std::exception& e)
		      {
			OPENVPN_LOG(e.what());
		      }
		  }
		if (fd == -1)
		  fd = Util::tuntap_open(config->layer, state->iface_name);
#                   else
		fd = UTun::utun_open(state->iface_name);
		tun_prefix = true;
#                   endif
	      }
	      catch (const std::exception& e)
		{
		  parent.tun_error(Error::TUN_IFACE_CREATE, e.what());
		  return;
		}

	      OPENVPN_LOG("open " << state->iface_name << " SUCCEEDED");

	      // create ASIO wrapper for tun fd
	      tun_wrap->save_replace_sock(new TUNStream(io_service, fd));

	      // initialize failsafe blocker
	      if (config->enable_failsafe_block && !config->fsblock)
		config->fsblock.reset(new FailsafeBlock);
	      FailsafeBlock* fsblock = config->fsblock.get();

	      // configure tun/tap interface properties
	      ActionList::Ptr add_cmds = new ActionList();
	      remove_cmds.reset(new ActionList());
	      remove_cmds->enable_destroy(true);
	      tun_wrap->add_destructor(remove_cmds);

	      // configure tun properties
	      tun_config(state->iface_name, *po, fsblock, *add_cmds, *remove_cmds);

	      // configure DNS
	      {
		MacDNS::Config::Ptr dns(new MacDNS::Config(*po));
		if (fsblock)
		  fsblock->add_dns(dns);
		else
		  MacDNSWatchdog::add_actions(dns, MacDNSWatchdog::FLUSH_RECONFIG, *add_cmds, *remove_cmds);
	      }

	      // configure failsafe blocker
	      if (fsblock)
		fsblock->establish(*add_cmds, *remove_cmds);

	      // execute commands to bring up interface
	      add_cmds->execute();

	      impl.reset(new TunImpl(tun_wrap,
				     state->iface_name,
				     true,
				     tun_prefix,
				     this,
				     config->frame,
				     config->stats
				     ));
	      impl->start(config->n_parallel);

	      // signal that we are connected
	      parent.tun_connected();
	    }
	    catch (const std::exception& e)
	      {
		if (tun_wrap)
		  tun_wrap->close();
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

      virtual void stop() { stop_(); }
      virtual ~Client() { stop_(); }

    private:
      Client(boost::asio::io_service& io_service_arg,
	     ClientConfig* config_arg,
	     TunClientParent& parent_arg)
	:  io_service(io_service_arg),
	   config(config_arg),
	   parent(parent_arg),
	   halt(false),
	   state(new TunProp::State())
      {
      }

      static void tun_config(const std::string& iface_name,
			     const TunBuilderCapture& pull,
			     FailsafeBlock* fsblock,
			     ActionList& create,
			     ActionList& destroy)
      {
	// get default gateway
	MacGWInfo gw;

	// set local4 and local6 to point to IPv4/6 route configurations
	const TunBuilderCapture::Route* local4 = NULL;
	const TunBuilderCapture::Route* local6 = NULL;
	if (pull.tunnel_address_index_ipv4 >= 0)
	  local4 = &pull.tunnel_addresses[pull.tunnel_address_index_ipv4];
	if (pull.tunnel_address_index_ipv6 >= 0)
	  local6 = &pull.tunnel_addresses[pull.tunnel_address_index_ipv6];

	// Interface down
	Command::Ptr iface_down(new Command);
	iface_down->argv.push_back("/sbin/ifconfig");
	iface_down->argv.push_back(iface_name);
	iface_down->argv.push_back("down");
	create.add(iface_down);

	// Set IPv4 Interface
	if (local4)
	  {
	    // Process ifconfig
	    const IPv4::Addr netmask = IPv4::Addr::netmask_from_prefix_len(local4->prefix_length);
	    {
	      Command::Ptr cmd(new Command);
	      cmd->argv.push_back("/sbin/ifconfig");
	      cmd->argv.push_back(iface_name);
	      cmd->argv.push_back(local4->address);
	      cmd->argv.push_back(local4->address);
	      cmd->argv.push_back("netmask");
	      cmd->argv.push_back(netmask.to_string());
	      cmd->argv.push_back("mtu");
	      cmd->argv.push_back(to_string(pull.mtu));
	      cmd->argv.push_back("up");
	      create.add(cmd);
	    }
	    add_del_route(local4->address, local4->prefix_length, local4->address, iface_name, 0, create, destroy);
	  }

	// Set IPv6 Interface
	if (local6)
	  {
	    {
	      Command::Ptr cmd(new Command);
	      cmd->argv.push_back("/sbin/ifconfig");
	      cmd->argv.push_back(iface_name);
	      cmd->argv.push_back("inet6");
	      cmd->argv.push_back(local6->address + '/' + to_string(local6->prefix_length));
	      cmd->argv.push_back("up");
	      create.add(cmd);
	    }
	    add_del_route(local6->address, local6->prefix_length, "", iface_name, R_IPv6|R_IFACE, create, destroy);
	  }

	// Process Routes
	{
	  for (std::vector<TunBuilderCapture::Route>::const_iterator i = pull.add_routes.begin(); i != pull.add_routes.end(); ++i)
	    {
	      const TunBuilderCapture::Route& route = *i;
	      if (route.ipv6)
		add_del_route(route.address, route.prefix_length, local6->gateway, iface_name, R_IPv6|R_IFACE, create, destroy);
	      else
		{
		  if (local4 && !local4->gateway.empty())
		    add_del_route(route.address, route.prefix_length, local4->gateway, iface_name, 0, create, destroy);
		  else
		    OPENVPN_LOG("ERROR: IPv4 route pushed without IPv4 ifconfig and/or route-gateway");
		}
	    }
	}

	// Process exclude routes
	if (!pull.exclude_routes.empty())
	  {
	    for (std::vector<TunBuilderCapture::Route>::const_iterator i = pull.exclude_routes.begin(); i != pull.exclude_routes.end(); ++i)
	      {
		const TunBuilderCapture::Route& route = *i;
		if (route.ipv6)
		  {
		    if (gw.v6.defined())
		      add_del_route(route.address, route.prefix_length, gw.v6.router.to_string(), gw.v6.iface, R_IPv6|R_IFACE_HINT, create, destroy);
		    else
		      OPENVPN_LOG("NOTE: cannot determine gateway for exclude IPv6 routes");
		  }
		else
		  {
		    if (gw.v4.defined())
		      add_del_route(route.address, route.prefix_length, gw.v4.router.to_string(), gw.v4.iface, 0, create, destroy);
		    else
		      OPENVPN_LOG("NOTE: cannot determine gateway for exclude IPv4 routes");
		  }
	      }
	  }

	// Process IPv4 redirect-gateway
	if (pull.reroute_gw.ipv4)
	  {
	    if (fsblock)
	      fsblock->add_block_v4();

	    // add server bypass route
	    if (gw.v4.defined())
	      {
		if (!pull.remote_address.ipv6)
		  {
		    Action::Ptr c, d;
		    add_del_route(pull.remote_address.address, 32, gw.v4.router.to_string(), gw.v4.iface, 0, c, d);
		    if (!fsblock || !fsblock->ip_hole_punch_exists(c))
		      {
			create.add(c);
			destroy.add(d);
		      }
		    //add_del_route(gw.v4.router.to_string(), 32, "", gw.v4.iface, R_ONLINK, create, destroy); // fixme -- needed for block-local
		  }
	      }
	    else
	      OPENVPN_LOG("ERROR: cannot detect IPv4 default gateway");

	    add_del_route("0.0.0.0", 2, local4->gateway, iface_name, 0, create, destroy);
	    add_del_route("64.0.0.0", 2, local4->gateway, iface_name, 0, create, destroy);
	    add_del_route("128.0.0.0", 2, local4->gateway, iface_name, 0, create, destroy);
	    add_del_route("192.0.0.0", 2, local4->gateway, iface_name, 0, create, destroy);
	  }

	// Process IPv6 redirect-gateway
	if (pull.reroute_gw.ipv6)
	  {
	    if (fsblock)
	      fsblock->add_block_v6();

	    // add server bypass route
	    if (gw.v6.defined())
	      {
		if (pull.remote_address.ipv6)
		  {
		    Action::Ptr c, d;
		    add_del_route(pull.remote_address.address, 128, gw.v6.router.to_string(), gw.v6.iface, R_IPv6|R_IFACE_HINT, c, d);
		    if (!fsblock || !fsblock->ip_hole_punch_exists(c))
		      {
			create.add(c);
			destroy.add(d);
		      }
		    //add_del_route(gw.v6.router.to_string(), 128, "", gw.v6.iface, R_IPv6|R_ONLINK, create, destroy); // fixme -- needed for block-local
		  }
	      }
	    else
	      OPENVPN_LOG("ERROR: cannot detect IPv6 default gateway");

	    add_del_route("0000::", 2, local6->gateway, iface_name, R_IPv6|R_IFACE, create, destroy);
	    add_del_route("4000::", 2, local6->gateway, iface_name, R_IPv6|R_IFACE, create, destroy);
	    add_del_route("8000::", 2, local6->gateway, iface_name, R_IPv6|R_IFACE, create, destroy);
	    add_del_route("C000::", 2, local6->gateway, iface_name, R_IPv6|R_IFACE, create, destroy);
	  }

	// Interface down
	destroy.add(iface_down);

	// Block IPv6
	if (pull.block_ipv6 && fsblock)
	  fsblock->add_block_v6_public();
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
			     const boost::system::error_code* error)
      {
      }

      void stop_()
      {
	if (!halt)
	  {
	    halt = true;

	    // stop tun
	    if (impl)
	      impl->stop();
	    tun_wrap.reset();
	  }
      }

      boost::asio::io_service& io_service;
      TunWrap::Ptr tun_wrap; // contains the tun device fd
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunImpl::Ptr impl;
      bool halt;
      TunProp::State::Ptr state;
      ActionList::Ptr remove_cmds;
    };

    inline TunClient::Ptr ClientConfig::new_client_obj(boost::asio::io_service& io_service,
						       TunClientParent& parent)
    {
      return TunClient::Ptr(new Client(io_service, this, parent));
    }

  }
} // namespace openvpn

#endif
