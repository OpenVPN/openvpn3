//
//  client.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TUN_BUILDER_CLIENT_H
#define OPENVPN_TUN_BUILDER_CLIENT_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/tun/tununixbase.hpp>
#include <openvpn/tun/builder/base.hpp>
#include <openvpn/tun/builder/capture.hpp>
#include <openvpn/addr/addrpair.hpp>
#include <openvpn/options/rgopt.hpp>

namespace openvpn {

  // Generic tun interface that drives a TunBuilderBase API.
  // Used on Android and iOS.
  namespace TunBuilderClient {

    // struct used to pass received tun packets
    struct PacketFrom
    {
      typedef ScopedPtr<PacketFrom> SPtr;
      BufferAllocated buf;
    };

    OPENVPN_EXCEPTION(tun_builder_error);
    OPENVPN_EXCEPTION(tun_builder_route_error);
    OPENVPN_EXCEPTION(tun_builder_dhcp_option_error);

    // A simplified tun interface where pre-existing
    // socket is provided.
    template <typename ReadHandler>
    class Tun : public TunUnixBase<ReadHandler, PacketFrom>
    {
      typedef TunUnixBase<ReadHandler, PacketFrom> Base;

    public:
      typedef boost::intrusive_ptr<Tun> Ptr;

      Tun(boost::asio::io_service& io_service,
	  const int socket,
	  const bool retain_sd_arg,
	  const bool tun_prefix_arg,
	  ReadHandler read_handler_arg,
	  const Frame::Ptr& frame_arg,
	  const SessionStats::Ptr& stats_arg)
	: Base(read_handler_arg, frame_arg, stats_arg)
      {
	Base::sd = new boost::asio::posix::stream_descriptor(io_service, socket);
	Base::name_ = "tun";
	Base::retain_sd = retain_sd_arg;
	Base::tun_prefix = tun_prefix_arg;
      }

      ~Tun() { Base::stop(); }
    };

    struct ClientState : public RC<thread_unsafe_refcount>
    {
      typedef boost::intrusive_ptr<ClientState> Ptr;

      IP::Addr vpn_ip4_addr;
      IP::Addr vpn_ip6_addr;
    };

    class TunPersist : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<TunPersist> Ptr;

      TunPersist() {}

      bool match(const std::string& options) const
      {
	return options == options_ && !options_.empty();
      }

      void persist(const int sd, const ClientState::Ptr& state, const std::string& options)
      {
	sd_.reset(sd);
	state_ = state;
	options_ = options;
      }

      int sd() const
      {
	return sd_();
      }

      const ClientState::Ptr& state() const
      {
	return state_;
      }

      void close()
      {
	sd_.close();
	state_.reset();
	options_ = "";
      }

      const std::string& options()
      {
	return options_;
      }

    private:
      ScopedFD sd_;
      ClientState::Ptr state_;
      std::string options_;
    };

    // A factory for the Client class
    class ClientConfig : public TunClientFactory
    {
    public:
      typedef boost::intrusive_ptr<ClientConfig> Ptr;

      std::string session_name;
      int mtu;                   // optional
      int n_parallel;            // number of parallel async reads on tun socket
      bool retain_sd;
      bool tun_prefix;
      Frame::Ptr frame;
      SessionStats::Ptr stats;

      TunPersist::Ptr tun_persist;

      TunBuilderBase* builder;

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_client_obj(boost::asio::io_service& io_service,
					    TunClientParent& parent);
    private:
      ClientConfig()
	: mtu(0), n_parallel(8), retain_sd(false), tun_prefix(false), builder(NULL) {}
    };

    // The tun interface
    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor
      friend class TunUnixBase<Client*, PacketFrom>;  // calls tun_read_handler

      typedef Tun<Client*> TunImpl;

      // IP version flags
      enum {
	F_IPv4=(1<<0),
	F_IPv6=(1<<1),
      };

      // add_dns flags
      enum {
	F_ADD_DNS=(1<<0),
      };

    public:
      virtual void client_start(const OptionList& opt, TransportClient& transcli)
      {
	if (!impl)
	  {
	    TunPersist::Ptr tun_persist = config->tun_persist;
	    halt = false;

	    try {
	      int sd = -1;
	      bool use_persisted_tun = false;
	      TunBuilderCapture::Ptr copt;

	      const IP::Addr server_addr = transcli.server_endpoint_addr();

	      // In tun_persist mode, capture tun builder settings so we can
	      // compare them to persisted settings.
	      if (tun_persist)
		{
		  copt.reset(new TunBuilderCapture());
		  try {
		    configure_builder(copt.get(), NULL, NULL, server_addr, *config, opt, true);
		  }
		  catch (const std::exception& e)
		    {
		      copt.reset();
		    }
		}

	      // Check if persisted tun session matches properties of to-be-created session
	      if (copt && tun_persist->match(copt->os.str()))
		{
		  sd = tun_persist->sd();
		  state = tun_persist->state();
		  use_persisted_tun = true;
		  OPENVPN_LOG("TunPersist: reused tun context");
		}
	      else
		{
		  TunBuilderBase* tb = config->builder;

		  // reset target tun builder object
		  if (!tb->tun_builder_new())
		    throw tun_builder_error("tun_builder_new failed");

		  // notify parent
		  parent.tun_pre_tun_config();

		  // configure the tun builder
		  configure_builder(tb, state.get(), config->stats.get(), server_addr, *config, opt, false);

		  // start tun
		  sd = tb->tun_builder_establish();
		}

	      if (sd == -1)
		{
		  parent.tun_error(Error::TUN_IFACE_CREATE, "cannot acquire tun interface socket");
		  return;
		}

	      // persist state
	      if (copt && !use_persisted_tun)
		{
		  tun_persist->persist(sd, state, copt->os.str());
		  OPENVPN_LOG("TunPersist: saving tun context:" << std::endl << tun_persist->options());
		}

	      impl.reset(new TunImpl(io_service,
				     sd,
				     (copt || use_persisted_tun) ? true : config->retain_sd,
				     config->tun_prefix,
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
		stop();
		if (tun_persist)
		  tun_persist->close();
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
	if (state->vpn_ip4_addr.defined())
	  return state->vpn_ip4_addr.to_string();
	else
	  return "";
      }

      virtual std::string vpn_ip6() const
      {
	if (state->vpn_ip6_addr.defined())
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
	   state(new ClientState())
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

      void stop_()
      {
	TunBuilderBase* tb = config->builder;
	if (!halt)
	  {
	    halt = true;

	    // stop tun
	    if (impl)
	      {
		tb->tun_builder_teardown();
		impl->stop();
	      }
	  }
      }

      static void configure_builder(TunBuilderBase* tb,
				    ClientState* state,
				    SessionStats* stats,
				    const IP::Addr& server_addr,
				    const ClientConfig& config,
				    const OptionList& opt,
				    const bool quiet)
      {
	// do ifconfig
	const unsigned int ip_ver_flags = tun_ifconfig(tb, state, opt);

	// add routes
	const unsigned int reroute_gw_ver_flags = add_routes(tb, opt, server_addr, ip_ver_flags);

	// Should all DNS requests be rerouted through pushed DNS servers?
	// (If false, only DNS requests that correspond to pushed domain prefixes
	// will be routed).
	const bool reroute_dns = should_reroute_dns(opt, reroute_gw_ver_flags, quiet);

	// add DNS servers and domain prefixes
	const unsigned int add_dns_flags = add_dns(tb, opt, reroute_dns, quiet);

	// set remote server address
	if (!tb->tun_builder_set_remote_address(server_addr.to_string(),
						server_addr.version() == IP::Addr::V6))
	  throw tun_builder_error("tun_builder_set_remote_address failed");

	// set MTU
	if (config.mtu)
	  {
	    if (!tb->tun_builder_set_mtu(config.mtu))
	      throw tun_builder_error("tun_builder_set_mtu failed");
	  }

	// set session name
	if (!config.session_name.empty())
	  {
	    if (!tb->tun_builder_set_session_name(config.session_name))
	      throw tun_builder_error("tun_builder_set_session_name failed");
	  }

	// warnings
	if (stats)
	  {
	    if ((reroute_gw_ver_flags & F_IPv4) && !(add_dns_flags & F_ADD_DNS))
	      stats->error(Error::REROUTE_GW_NO_DNS);
	  }
      }

      static bool should_reroute_dns(const OptionList& opt,
				     const unsigned int reroute_gw_ver_flags,
				     const bool quiet)
      {
	bool ret = bool(reroute_gw_ver_flags & F_IPv4);
	try {
	  const std::string& yes_no = opt.get_optional("redirect-dns", 1); // DIRECTIVE
	  if (!yes_no.empty())
	    {
	      if (yes_no == "yes")
		ret = true;
	      else if (yes_no == "no")
		ret = false;
	      else if (!quiet)
		OPENVPN_LOG("unknown redirect-dns option: " << yes_no);
	    }
	}
	catch (const std::exception& e)
	  {
	    if (!quiet)
	      OPENVPN_LOG("error parsing redirect-dns: " << e.what());
	  }
	return ret;
      }

      static unsigned int tun_ifconfig(TunBuilderBase* tb, ClientState* state, const OptionList& opt)
      {
	enum Topology {
	  NET30,
	  SUBNET,
	};

	unsigned int ip_ver_flags = 0;

	// get topology
	Topology top = NET30;
	{
	  const Option* o = opt.get_ptr("topology"); // DIRECTIVE
	  if (o)
	    {
	      o->min_args(2);
	      if ((*o)[1] == "subnet")
		top = SUBNET;
	      else if ((*o)[1] == "net30")
		top = NET30;
	      else
		throw option_error("only topology 'subnet' and 'net30' supported");
	    }
	}

	// configure tun interface
	{
	  const Option* o;
	  o = opt.get_ptr("ifconfig"); // DIRECTIVE
	  if (o)
	    {
	      if (top == SUBNET)
		{
		  o->min_args(2);
		  const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string((*o)[1], o->get_optional(2), "ifconfig");
		  if (pair.version() != IP::Addr::V4)
		    throw tun_builder_error("ifconfig address is not IPv4 (topology subnet)");
		  if (!tb->tun_builder_add_address(pair.addr.to_string(),
						   pair.netmask.prefix_len(),
						   false))
		    throw tun_builder_error("tun_builder_add_address IPv4 failed (topology subnet)");
		  if (state)
		    state->vpn_ip4_addr = pair.addr;
		  ip_ver_flags |= F_IPv4;
		}
	      else if (top == NET30)
		{
		  o->min_args(3);
		  const IP::Addr local = IP::Addr::from_string((*o)[1]);
		  const IP::Addr remote = IP::Addr::from_string((*o)[2]);
		  const IP::Addr netmask = IP::Addr::from_string("255.255.255.252");
		  if (local.version() != IP::Addr::V4 || remote.version() != IP::Addr::V4)
		    throw tun_builder_error("ifconfig address is not IPv4 (topology net30)");
		  if ((local & netmask) != (remote & netmask))
		    throw tun_builder_error("ifconfig addresses are not in the same /30 subnet (topology net30)");
		  if (!tb->tun_builder_add_address(local.to_string(),
						   netmask.prefix_len(),
						   false))
		    throw tun_builder_error("tun_builder_add_address IPv4 failed (topology net30)");
		  if (state)
		    state->vpn_ip4_addr = local;
		  ip_ver_flags |= F_IPv4;
		}
	      else
		throw option_error("internal topology error");
	    }

	  o = opt.get_ptr("ifconfig-ipv6"); // DIRECTIVE
	  if (o)
	    {
	      if (top != SUBNET)
		throw option_error("only topology 'subnet' supported with IPv6");
	      o->min_args(2);
	      const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string((*o)[1], "ifconfig-ipv6");
	      if (pair.version() != IP::Addr::V6)
		throw tun_builder_error("ifconfig-ipv6 address is not IPv6");
	      if (!tb->tun_builder_add_address(pair.addr.to_string(),
					       pair.netmask.prefix_len(),
					       true))
		throw tun_builder_error("tun_builder_add_address IPv6 failed");
	      if (state)
		state->vpn_ip6_addr = pair.addr;
	      ip_ver_flags |= F_IPv6;
	    }

	  if (!ip_ver_flags)
	    throw tun_builder_error("one of ifconfig or ifconfig-ipv6 must be specified");
	  return ip_ver_flags;
	}
      }

      static unsigned int add_routes(TunBuilderBase* tb,
				     const OptionList& opt,
				     const IP::Addr& server_addr,
				     const unsigned int ip_ver_flags)
      {
	unsigned int reroute_gw_ver_flags = 0;
	const RedirectGatewayFlags rg_flags(opt);

	// do redirect-gateway for IPv4
	if (rg_flags.redirect_gateway_ipv4_enabled() && (ip_ver_flags & F_IPv4))
	  {
	    if (!tb->tun_builder_reroute_gw(server_addr.to_string(),
					    server_addr.version() == IP::Addr::V6,
					    false))
	      throw tun_builder_route_error("tun_builder_reroute_gw for redirect-gateway IPv4 failed");
	    reroute_gw_ver_flags |= F_IPv4;
	  }

	// do redirect-gateway for IPv6
	if (rg_flags.redirect_gateway_ipv6_enabled() && (ip_ver_flags & F_IPv6))
	  {
	    if (!tb->tun_builder_reroute_gw(server_addr.to_string(),
					    server_addr.version() == IP::Addr::V6,
					    true))
	      throw tun_builder_route_error("tun_builder_reroute_gw for redirect-gateway IPv6 failed");
	    reroute_gw_ver_flags |= F_IPv6;
	  }
	
	// add IPv4 routes (if redirect-gateway IPv4 wasn't applied)
	if (!(reroute_gw_ver_flags & F_IPv4))
	  {
	    OptionList::IndexMap::const_iterator dopt = opt.map().find("route"); // DIRECTIVE
	    if (dopt != opt.map().end())
	      {
		for (OptionList::IndexList::const_iterator i = dopt->second.begin(); i != dopt->second.end(); ++i)
		  {
		    const Option& o = opt[*i];
		    try {
		      o.min_args(2);
		      if (o.size() >= 4 && o[3] != "vpn_gateway")
			throw tun_builder_route_error("only tunnel routes supported");
		      const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string(o[1], o.get_optional(2), "route");
		      if (!pair.is_canonical())
			throw tun_builder_error("route is not canonical");
		      if (pair.version() != IP::Addr::V4)
			throw tun_builder_error("route is not IPv4");
		      if (!tb->tun_builder_add_route(pair.addr.to_string(),
						     pair.netmask.prefix_len(),
						     false))
			throw tun_builder_route_error("tun_builder_add_route failed");
		    }
		    catch (const std::exception& e)
		      {
			OPENVPN_THROW(tun_builder_error, "error parsing IPv4 route: " << o.render() << " : " << e.what());
		      }
		  }
	      }
	  }

	// add IPv6 routes (if redirect-gateway IPv6 wasn't applied)
	if (!(reroute_gw_ver_flags & F_IPv6))
	  {
	    OptionList::IndexMap::const_iterator dopt = opt.map().find("route-ipv6"); // DIRECTIVE
	    if (dopt != opt.map().end())
	      {
		for (OptionList::IndexList::const_iterator i = dopt->second.begin(); i != dopt->second.end(); ++i)
		  {
		    const Option& o = opt[*i];
		    try {
		      o.min_args(2);
		      if (o.size() >= 3 && o[2] != "vpn_gateway")
			throw tun_builder_route_error("only tunnel routes supported");
		      const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string(o[1], "route-ipv6");
		      if (!pair.is_canonical())
			throw tun_builder_error("route is not canonical");
		      if (pair.version() != IP::Addr::V6)
			throw tun_builder_error("route is not IPv6");
		      if (!tb->tun_builder_add_route(pair.addr.to_string(),
						     pair.netmask.prefix_len(),
						     true))
			throw tun_builder_route_error("tun_builder_add_route failed");
		    }
		    catch (const std::exception& e)
		      {
			OPENVPN_THROW(tun_builder_error, "error parsing IPv6 route: " << o.render() << " : " << e.what());
		      }
		  }
	      }
	  }
	return reroute_gw_ver_flags;
      }

      static unsigned int add_dns(TunBuilderBase* tb, const OptionList& opt, const bool reroute_dns, const bool quiet)
      {
	// Example:
	//   [dhcp-option] [DNS] [172.16.0.23]
	//   [dhcp-option] [DOMAIN] [openvpn.net]
	//   [dhcp-option] [DOMAIN] [example.com]
	unsigned int flags = 0;
	OptionList::IndexMap::const_iterator dopt = opt.map().find("dhcp-option"); // DIRECTIVE
	if (dopt != opt.map().end())
	  {
	    for (OptionList::IndexList::const_iterator i = dopt->second.begin(); i != dopt->second.end(); ++i)
	      {
		const Option& o = opt[*i];
		try {
		  const std::string& type = o.get(1);
		  if (type == "DNS")
		    {
		      o.exact_args(3);
		      const IP::Addr ip = IP::Addr::from_string(o[2], "dns-server-ip");
		      if (!tb->tun_builder_add_dns_server(ip.to_string(),
							  ip.version() == IP::Addr::V6,
							  reroute_dns))
			throw tun_builder_dhcp_option_error("tun_builder_add_dns_server failed");
		      flags |= F_ADD_DNS;
		    }
		  else if (type == "DOMAIN")
		    {
		      o.exact_args(3);
		      if (!tb->tun_builder_add_search_domain(o[2], reroute_dns))
			throw tun_builder_dhcp_option_error("tun_builder_add_search_domain failed");
		    }
		  else if (!quiet)
		    OPENVPN_LOG("unknown DHCP option: " << o.render());
		}
		catch (const std::exception& e)
		  {
		    OPENVPN_THROW(tun_builder_error, "error parsing dhcp-option: " << o.render() << " : " << e.what());
		  }
	      }
	  }
	return flags;
      }

      boost::asio::io_service& io_service;
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunImpl::Ptr impl;
      bool halt;
      ClientState::Ptr state;
    };

    inline TunClient::Ptr ClientConfig::new_client_obj(boost::asio::io_service& io_service,
						       TunClientParent& parent)
    {
      return TunClient::Ptr(new Client(io_service, this, parent));
    }

  }
}

#endif
