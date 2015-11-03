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

// Client tun interface for Windows

#ifndef OPENVPN_TUN_WIN_CLIENT_TUNCLI_H
#define OPENVPN_TUN_WIN_CLIENT_TUNCLI_H

#include <string>
#include <sstream>
#include <memory>

#include <openvpn/common/size.hpp>
#include <openvpn/common/format.hpp>
#include <openvpn/common/arraysize.hpp>
#include <openvpn/common/scoped_asio_stream.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/tun/persist/tunpersist.hpp>
#include <openvpn/tun/persist/tunwrapasio.hpp>
#include <openvpn/tun/tunio.hpp>
#include <openvpn/tun/win/tunutil.hpp>
#include <openvpn/win/cmd.hpp>

#if _WIN32_WINNT >= 0x0600 // Vista+
#include <openvpn/tun/win/wfp.hpp>
#endif

namespace openvpn {
  namespace TunWin {

    OPENVPN_EXCEPTION(tun_win_error);

    // struct used to pass received tun packets
    struct PacketFrom
    {
      typedef std::unique_ptr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    // tun interface wrapper for Windows
    template <typename ReadHandler, typename TunPersist>
    class Tun : public TunIO<ReadHandler, PacketFrom, TunWrapAsioStream<TunPersist> >
    {
      typedef TunIO<ReadHandler, PacketFrom, TunWrapAsioStream<TunPersist>  > Base;

    public:
      typedef RCPtr<Tun> Ptr;

      Tun(const typename TunPersist::Ptr& tun_persist,
	  const std::string& name,
	  const bool retain_stream,
	  ReadHandler read_handler,
	  const Frame::Ptr& frame,
	  const SessionStats::Ptr& stats)
	: Base(read_handler, frame, stats)
      {
	Base::name_ = name;
	Base::retain_stream = retain_stream;
	Base::stream = new TunWrapAsioStream<TunPersist>(tun_persist);
      }
    };

    // These types manage the underlying TAP driver HANDLE
    typedef asio::windows::stream_handle TAPStream;
    typedef ScopedAsioStream<TAPStream> ScopedTAPStream;
    typedef TunPersistTemplate<ScopedTAPStream> TunPersist;

    class ClientConfig : public TunClientFactory
    {
      friend class Client; // accesses wfp

    public:
      typedef RCPtr<ClientConfig> Ptr;

      TunProp::Config tun_prop;
      int n_parallel = 8;         // number of parallel async reads on tun socket

      Frame::Ptr frame;
      SessionStats::Ptr stats;

      TunPersist::Ptr tun_persist;

      ActionListFactory::Ptr action_list_factory;

      ActionList::Ptr new_action_list()
      {
	if (action_list_factory)
	  return action_list_factory->new_action_list();
	else
	  return new ActionList();
      }

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_tun_client_obj(asio::io_context& io_context,
						TunClientParent& parent,
						TransportClient* transcli);

      virtual void finalize(const bool disconnected)
      {
	if (disconnected)
	  {
	    tun_persist.reset();
#if _WIN32_WINNT >= 0x0600 // Vista+
	    wfp.reset();
#endif
	  }
      }

    private:
#if _WIN32_WINNT >= 0x0600 // Vista+
      TunWin::WFPContext::Ptr wfp{new TunWin::WFPContext};
#endif
    };

    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor
      friend class TunIO<Client*, PacketFrom, TunWrapAsioStream<TunPersist> >;  // calls tun_read_handler

      typedef Tun<Client*, TunPersist> TunImpl;

    public:
      virtual void tun_start(const OptionList& opt, TransportClient& transcli, CryptoDCSettings&)
      {
	if (!impl)
	  {
	    halt = false;
	    if (config->tun_persist)
	      tun_persist = config->tun_persist; // long-term persistent
	    else
	      tun_persist.reset(new TunPersist(false, false, nullptr)); // short-term

	    try {
	      const IP::Addr server_addr = transcli.server_endpoint_addr();

	      // Check if persisted tun session matches properties of to-be-created session
	      if (tun_persist->use_persisted_tun(server_addr, config->tun_prop, opt))
		{
		  state = tun_persist->state();
		  OPENVPN_LOG("TunPersist: reused tun context");
		}
	      else
		{
		  // notify parent
		  parent.tun_pre_tun_config();

		  // close old TAP handle if persisted
		  tun_persist->close();

		  // enumerate available TAP adapters
		  Util::TapNameGuidPairList guids;
		  OPENVPN_LOG("TAP ADAPTERS:" << std::endl << guids.to_string());

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
		  OPENVPN_LOG("CAPTURED OPTIONS:" << std::endl << po->to_string()); // fixme

		  // open TAP device handle
		  std::string path_opened;
		  Util::TapNameGuidPair tap;
		  HANDLE th = Util::tap_open(guids, path_opened, tap);
		  const std::string msg = "Open TAP device \"" + tap.name + "\" PATH=\"" + path_opened + '\"';

		  if (!Win::Handle::defined(th))
		    {
		      OPENVPN_LOG(msg << " FAILED");
		      parent.tun_error(Error::TUN_IFACE_CREATE, "cannot acquire TAP handle");
		      return;
		    }

		  OPENVPN_LOG(msg << " SUCCEEDED");
		  Util::TAPDriverVersion version(th);
		  OPENVPN_LOG(version.to_string());

		  // create ASIO wrapper for HANDLE
		  TAPStream* ts = new TAPStream(io_context, th);

		  // persist tun settings state
		  if (tun_persist->persist_tun_state(ts, state))
		    OPENVPN_LOG("TunPersist: saving tun context:" << std::endl << tun_persist->options());

		  // create ActionLists for setting up and removing adapter properties
		  ActionList::Ptr add_cmds = config->new_action_list();
		  remove_cmds = config->new_action_list();

		  // populate add/remove lists with actions
		  if (!adapter_config(th, tap, *po, *add_cmds, *remove_cmds))
		    return;

		  // execute the add actions
		  if (!execute_actions(*add_cmds))
		    return;

		  // now that the add actions have succeeded,
		  // enable the remove actions
		  remove_cmds->enable_destroy(true);
		  tun_persist->add_destructor(remove_cmds);
		}

	      // configure tun interface packet forwarding
	      impl.reset(new TunImpl(tun_persist,
				     "TUN_WIN",
				     true,
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
		if (tun_persist)
		  tun_persist->close();
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
	   halt(false),
	   state(new TunProp::State())
      {
      }

      bool execute_actions(ActionList& actions)
      {
	std::ostringstream os;
	try {
	  actions.execute(os);
	}
	catch (const std::exception& e)
	  {
	    OPENVPN_LOG_STRING(os.str());
	    parent.tun_error(Error::TUN_SETUP_FAILED, e.what());
	    return false;
	  }
	OPENVPN_LOG_STRING(os.str());
	return true;
      }

#if _WIN32_WINNT >= 0x0600
      // Configure TAP adapter on Vista and higher
      bool adapter_config(HANDLE th,
			  const Util::TapNameGuidPair& tap,
			  const TunBuilderCapture& pull,
			  ActionList& create,
			  ActionList& destroy)
      {
	// Windows interface index
	const std::string tap_index_name = tap.index_or_name();

	// special IPv6 next-hop recognized by TAP driver (magic)
	const std::string ipv6_next_hop = "fe80::8";

	// get default gateway
	const Util::DefaultGateway gw;

	// set local4 and local6 to point to IPv4/6 route configurations
	const TunBuilderCapture::Route* local4 = pull.vpn_ipv4();
	const TunBuilderCapture::Route* local6 = pull.vpn_ipv6();

	// set TAP media status to CONNECTED
	Util::tap_set_media_status(th, true);

	// try to delete any stale routes on interface left over from previous session
	create.add(new Util::ActionDeleteAllRoutesOnInterface(tap.index));

	// Set IPv4 Interface
	//
	// Usage: set address [name=]<string>
	//  [[source=]dhcp|static]
	//  [[address=]<IPv4 address>[/<integer>] [[mask=]<IPv4 mask>]
	//  [[gateway=]<IPv4 address>|none [gwmetric=]<integer>]
	//  [[type=]unicast|anycast]
	//  [[subinterface=]<string>]
	//  [[store=]active|persistent]
	// Usage: delete address [name=]<string> [[address=]<IPv4 address>]
	//  [[gateway=]<IPv4 address>|all]
	//  [[store=]active|persistent]
	if (local4)
	  {
	    // Process ifconfig and topology
	    const std::string netmask = IPv4::Addr::netmask_from_prefix_len(local4->prefix_length).to_string();
	    const IP::Addr localaddr = IP::Addr::from_string(local4->address);
	    if (local4->net30)
	      Util::tap_configure_topology_net30(th, localaddr, local4->prefix_length);
	    else
	      Util::tap_configure_topology_subnet(th, localaddr, local4->prefix_length);
	    create.add(new WinCmd("netsh interface ip set address " + tap_index_name + " static " + local4->address + ' ' + netmask + " gateway=" + local4->gateway + " store=active"));
	    destroy.add(new WinCmd("netsh interface ip delete address " + tap_index_name + ' ' + local4->address + " gateway=all store=active"));
	  }

	// Should we block IPv6?
	if (pull.block_ipv6)
	  {
	    static const char *const block_ipv6_net[] = {
	      "2000::/4",
	      "3000::/4",
	      "fc00::/7",
	    };
	    for (size_t i = 0; i < array_size(block_ipv6_net); ++i)
	      {
		create.add(new WinCmd("netsh interface ipv6 add route " + std::string(block_ipv6_net[i]) + " interface=1 store=active"));
		destroy.add(new WinCmd("netsh interface ipv6 delete route " + std::string(block_ipv6_net[i]) + " interface=1 store=active"));
	      }
	  }

	// Set IPv6 Interface
	//
	// Usage: set address [interface=]<string> [address=]<IPv6 address>
	//  [[type=]unicast|anycast]
	//  [[validlifetime=]<integer>|infinite]
	//  [[preferredlifetime=]<integer>|infinite]
	//  [[store=]active|persistent]
	//Usage: delete address [interface=]<string> [address=]<IPv6 address>
	//  [[store=]active|persistent]
	if (local6 && !pull.block_ipv6)
	  {
	    create.add(new WinCmd("netsh interface ipv6 set address " + tap_index_name + ' ' + local6->address + " store=active"));
	    destroy.add(new WinCmd("netsh interface ipv6 delete address " + tap_index_name + ' ' + local6->address + " store=active"));

	    create.add(new WinCmd("netsh interface ipv6 add route " + local6->gateway + '/' + to_string(local6->prefix_length) + ' ' + tap_index_name + ' ' + ipv6_next_hop + " store=active"));
	    destroy.add(new WinCmd("netsh interface ipv6 delete route " + local6->gateway + '/' + to_string(local6->prefix_length) + ' ' + tap_index_name + ' ' + ipv6_next_hop + " store=active"));
	  }

	// Process Routes
	//
	// Usage: add route [prefix=]<IPv4 address>/<integer> [interface=]<string>
	//  [[nexthop=]<IPv4 address>] [[siteprefixlength=]<integer>]
	//  [[metric=]<integer>] [[publish=]no|age|yes]
	//  [[validlifetime=]<integer>|infinite]
	//  [[preferredlifetime=]<integer>|infinite]
	//  [[store=]active|persistent]
	// Usage: delete route [prefix=]<IPv4 address>/<integer> [interface=]<string>
	//  [[nexthop=]<IPv4 address>]
	//  [[store=]active|persistent]
	//
	// Usage: add route [prefix=]<IPv6 address>/<integer> [interface=]<string>
	//  [[nexthop=]<IPv6 address>] [[siteprefixlength=]<integer>]
	//  [[metric=]<integer>] [[publish=]no|age|yes]
	//  [[validlifetime=]<integer>|infinite]
	//  [[preferredlifetime=]<integer>|infinite]
	//  [[store=]active|persistent]
	// Usage: delete route [prefix=]<IPv6 address>/<integer> [interface=]<string>
	//  [[nexthop=]<IPv6 address>]
	//  [[store=]active|persistent]
	{
	  for (auto &route : pull.add_routes)
	    {
	      if (route.ipv6)
		{
		  if (!pull.block_ipv6)
		    {
		      create.add(new WinCmd("netsh interface ipv6 add route " + route.address + '/' + to_string(route.prefix_length) + ' ' + tap_index_name + ' ' + ipv6_next_hop + " store=active"));
		      destroy.add(new WinCmd("netsh interface ipv6 delete route " + route.address + '/' + to_string(route.prefix_length) + ' ' + tap_index_name + ' ' + ipv6_next_hop + " store=active"));
		    }
		}
	      else
		{
		  if (local4)
		    {
		      create.add(new WinCmd("netsh interface ip add route " + route.address + '/' + to_string(route.prefix_length) + ' ' + tap_index_name + ' ' + local4->gateway + " store=active"));
		      destroy.add(new WinCmd("netsh interface ip delete route " + route.address + '/' + to_string(route.prefix_length) + ' ' + tap_index_name + ' ' + local4->gateway + " store=active"));
		    }
		  else
		    throw tun_win_error("IPv4 routes pushed without IPv4 ifconfig");
		}
	    }
	}

	// Process exclude routes
	if (!pull.exclude_routes.empty())
	  {
	    if (gw.defined())
	      {
		bool ipv6_error = false;
		for (std::vector<TunBuilderCapture::Route>::const_iterator i = pull.exclude_routes.begin(); i != pull.exclude_routes.end(); ++i)
		  {
		    const TunBuilderCapture::Route& route = *i;
		    if (route.ipv6)
		      {
			ipv6_error = true;
		      }
		    else
		      {
			create.add(new WinCmd("netsh interface ip add route " + route.address + '/' + to_string(route.prefix_length) + ' ' + to_string(gw.interface_index()) + ' ' + gw.gateway_address() + " store=active"));
			destroy.add(new WinCmd("netsh interface ip delete route " + route.address + '/' + to_string(route.prefix_length) + ' ' + to_string(gw.interface_index()) + ' ' + gw.gateway_address() + " store=active"));
		      }
		  }
		if (ipv6_error)
		  OPENVPN_LOG("NOTE: exclude IPv6 routes not currently supported");
	      }
	    else
	      OPENVPN_LOG("NOTE: exclude routes error: cannot detect default gateway");
	  }

	// Process IPv4 redirect-gateway
	if (pull.reroute_gw.ipv4)
	  {
	    // add server bypass route
	    if (gw.defined())
	      {
		if (!pull.remote_address.ipv6)
		  {
		    create.add(new WinCmd("netsh interface ip add route " + pull.remote_address.address + "/32 " + to_string(gw.interface_index()) + ' ' + gw.gateway_address() + " store=active"));
		    destroy.add(new WinCmd("netsh interface ip delete route " + pull.remote_address.address + "/32 " + to_string(gw.interface_index()) + ' ' + gw.gateway_address() + " store=active"));
		  }
	      }
	    else
	      throw tun_win_error("redirect-gateway error: cannot detect default gateway");

	    create.add(new WinCmd("netsh interface ip add route 0.0.0.0/1 " + tap_index_name + ' ' + local4->gateway + " store=active"));
	    create.add(new WinCmd("netsh interface ip add route 128.0.0.0/1 " + tap_index_name + ' ' + local4->gateway + " store=active"));
	    destroy.add(new WinCmd("netsh interface ip delete route 0.0.0.0/1 " + tap_index_name + ' ' + local4->gateway + " store=active"));
	    destroy.add(new WinCmd("netsh interface ip delete route 128.0.0.0/1 " + tap_index_name + ' ' + local4->gateway + " store=active"));
	  }

	// Process IPv6 redirect-gateway
	if (pull.reroute_gw.ipv6 && !pull.block_ipv6)
	  {
	    create.add(new WinCmd("netsh interface ipv6 add route 0::/1 " + tap_index_name + ' ' + ipv6_next_hop + " store=active"));
	    create.add(new WinCmd("netsh interface ipv6 add route 8000::/1 " + tap_index_name + ' ' + ipv6_next_hop + " store=active"));
	    destroy.add(new WinCmd("netsh interface ipv6 delete route 0::/1 " + tap_index_name + ' ' + ipv6_next_hop + " store=active"));
	    destroy.add(new WinCmd("netsh interface ipv6 delete route 8000::/1 " + tap_index_name + ' ' + ipv6_next_hop + " store=active"));
	  }

	// Process DNS Servers
	//
	// Usage: set dnsservers [name=]<string> [source=]dhcp|static
	//  [[address=]<IP address>|none]
	//  [[register=]none|primary|both]
	//  [[validate=]yes|no]
	// Usage: add dnsservers [name=]<string> [address=]<IPv4 address>
	//  [[index=]<integer>] [[validate=]yes|no]
	// Usage: delete dnsservers [name=]<string> [[address=]<IP address>|all] [[validate=]yes|no]
	//
	// Usage: set dnsservers [name=]<string> [source=]dhcp|static
	//  [[address=]<IPv6 address>|none]
	//  [[register=]none|primary|both]
	//  [[validate=]yes|no]
	// Usage: add dnsservers [name=]<string> [address=]<IPv6 address>
	//  [[index=]<integer>] [[validate=]yes|no]
	// Usage: delete dnsservers [name=]<string> [[address=]<IPv6 address>|all] [[validate=]yes|no]
	{
	  int indices[2] = {0, 0}; // per-protocol indices
	  for (size_t i = 0; i < pull.dns_servers.size(); ++i)
	    {
	      const TunBuilderCapture::DNSServer& ds = pull.dns_servers[i];
	      if (ds.ipv6 && pull.block_ipv6)
		continue;
	      const std::string proto = ds.ipv6 ? "ipv6" : "ip";
	      const int idx = indices[bool(ds.ipv6)]++;
	      if (idx)
		create.add(new WinCmd("netsh interface " + proto + " add dnsservers " + tap_index_name + ' ' + ds.address + " " + to_string(idx+1) + " validate=no"));
	      else
		{
		  create.add(new WinCmd("netsh interface " + proto + " set dnsservers " + tap_index_name + " static " + ds.address + " register=primary validate=no"));
		  destroy.add(new WinCmd("netsh interface " + proto + " delete dnsservers " + tap_index_name + " all validate=no"));
		}
	    }

	  // If we added DNS servers, block DNS on all interfaces except
	  // the TAP adapter.
	  if (indices[0] || indices[1])
	    {
	      create.add(new ActionWFP(tap.index, true, config->wfp));
	      destroy.add(new ActionWFP(tap.index, false, config->wfp));
	    }
	}

	// Process DNS search domains
	if (!pull.search_domains.empty())
	  {
	    // Only the first search domain is used (Windows limitation?)
	    create.add(new Util::ActionSetSearchDomain(pull.search_domains[0].domain, tap.guid));
	    destroy.add(new Util::ActionSetSearchDomain("", tap.guid));
	  }

	// Process WINS Servers
	//
	// Usage: set winsservers [name=]<string> [source=]dhcp|static
	//  [[address=]<IP address>|none]
	// Usage: add winsservers [name=]<string> [address=]<IP address> [[index=]<integer>]
	// Usage: delete winsservers [name=]<string> [[address=]<IP address>|all]
	{
	  for (size_t i = 0; i < pull.wins_servers.size(); ++i)
	    {
	      const TunBuilderCapture::WINSServer& ws = pull.wins_servers[i];
	      if (i)
		create.add(new WinCmd("netsh interface ip add winsservers " + tap_index_name + ' ' + ws.address + ' ' + to_string(i+1)));
	      else
		{
		  create.add(new WinCmd("netsh interface ip set winsservers " + tap_index_name + " static " + ws.address));
		  destroy.add(new WinCmd("netsh interface ip delete winsservers " + tap_index_name + " all"));
		}
	    }
	}

	// flush DNS cache
	create.add(new WinCmd("ipconfig /flushdns"));
	destroy.add(new WinCmd("ipconfig /flushdns"));
	return true;
      }
#else
      // Configure TAP adapter for pre-Vista
      // Currently we don't support IPv6 on pre-Vista
      bool adapter_config(HANDLE th,
			  const Util::TapNameGuidPair& tap,
			  const TunBuilderCapture& pull,
			  ActionList& create,
			  ActionList& destroy)
      {
	// Windows interface index
	const std::string tap_index_name = tap.index_or_name();

	// get default gateway
	const Util::DefaultGateway gw;

	// set local4 to point to IPv4 route configurations
	const TunBuilderCapture::Route* local4 = pull.vpn_ipv4();

	// Make sure the TAP adapter is set for DHCP
	{
	  const Util::IPAdaptersInfo ai;
	  if (!ai.is_dhcp_enabled(tap.index))
	    {
	      OPENVPN_LOG("TAP: DHCP is disabled, attempting to enable");
	      ActionList::Ptr cmds = config->new_action_list();
	      cmds->add(new Util::ActionEnableDHCP(tap));
	      if (!execute_actions(*cmds))
		return false;
	    }
	}

	// Set IPv4 Interface
	if (local4)
	  {
	    // Process ifconfig and topology
	    const std::string netmask = IPv4::Addr::netmask_from_prefix_len(local4->prefix_length).to_string();
	    const IP::Addr localaddr = IP::Addr::from_string(local4->address);
	    if (local4->net30)
	      Util::tap_configure_topology_net30(th, localaddr, local4->prefix_length);
	    else
	      Util::tap_configure_topology_subnet(th, localaddr, local4->prefix_length);
	  }

	// On pre-Vista, set up TAP adapter DHCP masquerade for
	// configuring adapter properties.
	{
	  OPENVPN_LOG("TAP: configure DHCP masquerade");
	  Util::TAPDHCPMasquerade dhmasq;
	  dhmasq.init_from_capture(pull);
	  dhmasq.ioctl(th);
	}

	// set TAP media status to CONNECTED
	Util::tap_set_media_status(th, true);

	// ARP
	Util::flush_arp(tap.index);

	// DHCP release/renew
	{
	  const Util::InterfaceInfoList ii;
	  Util::dhcp_release(ii, tap.index);
	  Util::dhcp_renew(ii, tap.index);
	}

	// Wait for TAP adapter to come up
	{
	  bool succeed = false;
	  const Util::IPNetmask4 vpn_addr(pull, "VPN IP");
	  for (int i = 1; i <= 30; ++i)
	    {
	      OPENVPN_LOG('[' << i << "] waiting for TAP adapter to receive DHCP settings...");
	      const Util::IPAdaptersInfo ai;
	      if (ai.is_up(tap.index, vpn_addr))
		{
		  succeed = true;
		  break;
		}
	      ::Sleep(1000);
	    }
	  if (!succeed)
	    throw tun_win_error("TAP adapter DHCP handshake failed");
	}

	// Process routes
	for (auto &route : pull.add_routes)
	  {
	    if (!route.ipv6)
	      {
		if (local4)
		  {
		    const std::string netmask = IPv4::Addr::netmask_from_prefix_len(route.prefix_length).to_string();
		    create.add(new WinCmd("route ADD " + route.address + " MASK " + netmask + ' ' + local4->gateway));
		    destroy.add(new WinCmd("route DELETE " + route.address + " MASK " + netmask + ' ' + local4->gateway));
		  }
		else
		  throw tun_win_error("IPv4 routes pushed without IPv4 ifconfig");
	      }
	  }

	// Process exclude routes
	if (!pull.exclude_routes.empty())
	  {
	    if (gw.defined())
	      {
		for (auto &route : pull.exclude_routes)
		  {
		    if (!route.ipv6)
		      {
			const std::string netmask = IPv4::Addr::netmask_from_prefix_len(route.prefix_length).to_string();
			create.add(new WinCmd("route ADD " + route.address + " MASK " + netmask + ' ' + gw.gateway_address()));
			destroy.add(new WinCmd("route DELETE " + route.address + " MASK " + netmask + ' ' + gw.gateway_address()));
		      }
		  }
	      }
	    else
	      OPENVPN_LOG("NOTE: exclude routes error: cannot detect default gateway");
	  }

	// Process IPv4 redirect-gateway
	if (pull.reroute_gw.ipv4)
	  {
	    // add server bypass route
	    if (gw.defined())
	      {
		if (!pull.remote_address.ipv6)
		  {
		    create.add(new WinCmd("route ADD " + pull.remote_address.address + " MASK 255.255.255.255 " + gw.gateway_address()));
		    destroy.add(new WinCmd("route DELETE " + pull.remote_address.address + " MASK 255.255.255.255 " + gw.gateway_address()));
		  }
	      }
	    else
	      throw tun_win_error("redirect-gateway error: cannot detect default gateway");

	    create.add(new WinCmd("route ADD 0.0.0.0 MASK 128.0.0.0 " + local4->gateway));
	    create.add(new WinCmd("route ADD 128.0.0.0 MASK 128.0.0.0 " + local4->gateway));
	    destroy.add(new WinCmd("route DELETE 0.0.0.0 MASK 128.0.0.0 " + local4->gateway));
	    destroy.add(new WinCmd("route DELETE 128.0.0.0 MASK 128.0.0.0 " + local4->gateway));
	  }

	// flush DNS cache
	//create.add(new WinCmd("net stop dnscache"));
	//create.add(new WinCmd("net start dnscache"));
	create.add(new WinCmd("ipconfig /flushdns"));
	//create.add(new WinCmd("ipconfig /registerdns"));
	destroy.add(new WinCmd("ipconfig /flushdns"));
	return true;
      }
#endif

      bool send(Buffer& buf)
      {
	if (impl)
	  return impl->write(buf);
	else
	  return false;
#ifdef OPENVPN_DEBUG_TAPWIN
	tap_process_logging();
#endif
      }

      void tun_read_handler(PacketFrom::SPtr& pfp) // called by TunImpl
      {
	parent.tun_recv(pfp->buf);
#ifdef OPENVPN_DEBUG_TAPWIN
	tap_process_logging();
#endif
      }

      void tun_error_handler(const Error::Type errtype, // called by TunImpl
			     const asio::error_code* error)
      {
	if (errtype == Error::TUN_READ_ERROR && error && error->value() == 995)
	  parent.tun_error(Error::TUN_IFACE_DISABLED, "TAP adapter is disabled");
      }

      void stop_()
      {
	if (!halt)
	  {
	    halt = true;

	    // stop tun
	    if (impl)
	      impl->stop();
	    tun_persist.reset();
	  }
      }

      HANDLE tap_handle()
      {
	if (tun_persist)
	  {
	    TAPStream* stream = tun_persist->obj();
	    if (stream)
	      return stream->native_handle();
	  }
	return Win::Handle::undefined();
      }

      void tap_process_logging()
      {
	HANDLE h = tap_handle();
	if (Win::Handle::defined(h))
	  Util::tap_process_logging(h);
      }

      asio::io_context& io_context;
      TunPersist::Ptr tun_persist; // contains the TAP device HANDLE
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunImpl::Ptr impl;
      bool halt;
      TunProp::State::Ptr state;
      ActionList::Ptr remove_cmds;
    };

    inline TunClient::Ptr ClientConfig::new_tun_client_obj(asio::io_context& io_context,
							   TunClientParent& parent,
							   TransportClient* transcli)
    {
      return TunClient::Ptr(new Client(io_context, this, parent));
    }

  }
} // namespace openvpn

#endif
