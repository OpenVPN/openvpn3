//
//  client.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Generic, cross-platform tun interface that drives a TunBuilderBase API.
// Fully supports IPv6.  To make this work on a given platform, define
// a TunBuilderBase for the platform.

#ifndef OPENVPN_TUN_BUILDER_CLIENT_H
#define OPENVPN_TUN_BUILDER_CLIENT_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/scoped_fd.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/tun/tununixbase.hpp>
#include <openvpn/tun/builder/base.hpp>
#include <openvpn/tun/builder/capture.hpp>
#include <openvpn/addr/addrpair.hpp>
#include <openvpn/client/rgopt.hpp>

namespace openvpn {
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

      TunPersist(const bool retain_sd, TunBuilderBase* tb)
	: retain_sd_(retain_sd), tb_(tb) {}

      bool defined() const
      {
	return sd_.defined();
      }

      bool match(const std::string& options) const
      {
	return options == options_ && !options_.empty();
      }

      void persist(const int sd, const ClientState::Ptr& state, const std::string& options)
      {
	if (retain_sd_)
	  sd_.replace(sd);
	else
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

      ~TunPersist()
      {
	close();
      }

      void close()
      {
	if (tb_)
	  tb_->tun_builder_teardown();
	if (retain_sd_)
	  sd_.release();
	else
	  sd_.close();
	state_.reset();
	options_ = "";
      }

      const std::string& options()
      {
	return options_;
      }

    private:
      bool retain_sd_;
      TunBuilderBase* tb_;
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
      bool google_dns_fallback;
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
	: mtu(0), n_parallel(8), retain_sd(false), tun_prefix(false), google_dns_fallback(false), builder(NULL) {}
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
	      if (copt && tun_persist->match(copt->to_string()))
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
		  tun_persist->persist(sd, state, copt->to_string());
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
		// if tun_persist is defined, it owns the sd and takes responsibility for teardown
		if (!config->tun_persist)
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

	// add DNS servers and domain prefixes
	const unsigned int add_dns_flags = add_dns(tb, opt, quiet);

	// DNS fallback
	if ((reroute_gw_ver_flags & F_IPv4) && !(add_dns_flags & F_ADD_DNS))
	  {
	    if (config.google_dns_fallback)
	      add_google_dns(tb);
	    else if (stats)
	      stats->error(Error::REROUTE_GW_NO_DNS);
	  }

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
	  const Option* o = opt.get_consistent("topology"); // DIRECTIVE
	  if (o)
	    {
              const std::string& topstr = o->get(1, 16);
	      if (topstr == "subnet")
		top = SUBNET;
	      else if (topstr == "net30")
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
		  const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string(o->get(1, 256), o->get_optional(2, 256), "ifconfig");
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
		  const IP::Addr remote = IP::Addr::from_string(o->get(2, 256));
		  const IP::Addr local = IP::Addr::from_string(o->get(1, 256));
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
	      const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string(o->get(1, 256), "ifconfig-ipv6");
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

      static void add_exclude_route(TunBuilderBase* tb, 
				    bool add,
				    const std::string& address,
				    int prefix_length,
				    bool ipv6)
      {
	if (add)
	  {
	    if (!tb->tun_builder_add_route(address, prefix_length, ipv6))
	      throw tun_builder_route_error("tun_builder_add_route failed");
	  }
	else
	  {
	    if (!tb->tun_builder_exclude_route(address, prefix_length, ipv6))
	      throw tun_builder_route_error("tun_builder_exclude_route failed");
	  }
      }

      // Check the target of a route.
      // Return true if route should be added or false if route should be excluded.
      static bool route_target(const Option& o, const size_t target_index)
      {
	if (o.size() >= (target_index+1))
	  {
	    const std::string& target = o.ref(target_index);
	    if (target == "vpn_gateway")
	      return true;
	    else if (target == "net_gateway")
	      return false;
	    else
	      throw tun_builder_route_error("route destinations other than vpn_gateway or net_gateway are not supported");
	  }
	else
	  return true;
      }

      static unsigned int add_routes(TunBuilderBase* tb,
				     const OptionList& opt,
				     const IP::Addr& server_addr,
				     const unsigned int ip_ver_flags)
      {
	unsigned int reroute_gw_ver_flags = 0;
	const RedirectGatewayFlags rg_flags(opt);

	// redirect-gateway enabled for IPv4?
	if (rg_flags.redirect_gateway_ipv4_enabled() && (ip_ver_flags & F_IPv4))
	  reroute_gw_ver_flags |= F_IPv4;

	// redirect-gateway enabled for IPv6?
	if (rg_flags.redirect_gateway_ipv6_enabled() && (ip_ver_flags & F_IPv6))
	  reroute_gw_ver_flags |= F_IPv6;

	// call reroute_gw builder method
	if (!tb->tun_builder_reroute_gw(server_addr.to_string(),
					server_addr.version() == IP::Addr::V6,
					(reroute_gw_ver_flags & F_IPv4) ? true : false,
					(reroute_gw_ver_flags & F_IPv6) ? true : false,
					rg_flags()))
	  throw tun_builder_route_error("tun_builder_reroute_gw for redirect-gateway failed");

	// add IPv4 routes
	if (ip_ver_flags & F_IPv4)
	  {
	    OptionList::IndexMap::const_iterator dopt = opt.map().find("route"); // DIRECTIVE
	    if (dopt != opt.map().end())
	      {
		for (OptionList::IndexList::const_iterator i = dopt->second.begin(); i != dopt->second.end(); ++i)
		  {
		    const Option& o = opt[*i];
		    try {
		      const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string(o.get(1, 256), o.get_optional(2, 256), "route");
		      if (!pair.is_canonical())
			throw tun_builder_error("route is not canonical");
		      if (pair.version() != IP::Addr::V4)
			throw tun_builder_error("route is not IPv4");
		      const bool add = route_target(o, 3);
		      if (!(reroute_gw_ver_flags & F_IPv4) || !add)
			add_exclude_route(tb, add, pair.addr.to_string(), pair.netmask.prefix_len(), false);
		    }
		    catch (const std::exception& e)
		      {
			OPENVPN_LOG("Error parsing IPv4 route: " << o.render() << " : " << e.what());
		      }
		  }
	      }
	  }

	// add IPv6 routes
	if (ip_ver_flags & F_IPv6)
	  {
	    OptionList::IndexMap::const_iterator dopt = opt.map().find("route-ipv6"); // DIRECTIVE
	    if (dopt != opt.map().end())
	      {
		for (OptionList::IndexList::const_iterator i = dopt->second.begin(); i != dopt->second.end(); ++i)
		  {
		    const Option& o = opt[*i];
		    try {
		      const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string(o.get(1, 256), "route-ipv6");
		      if (!pair.is_canonical())
			throw tun_builder_error("route is not canonical");
		      if (pair.version() != IP::Addr::V6)
			throw tun_builder_error("route is not IPv6");
		      const bool add = route_target(o, 2);
		      if (!(reroute_gw_ver_flags & F_IPv6) || !add)
			add_exclude_route(tb, add, pair.addr.to_string(), pair.netmask.prefix_len(), true);
		    }
		    catch (const std::exception& e)
		      {
			OPENVPN_LOG("Error parsing IPv6 route: " << o.render() << " : " << e.what());
		      }
		  }
	      }
	  }
	return reroute_gw_ver_flags;
      }

      static unsigned int add_dns(TunBuilderBase* tb, const OptionList& opt, const bool quiet)
      {
	// Example:
	//   [dhcp-option] [DNS] [172.16.0.23]
	//   [dhcp-option] [DOMAIN] [openvpn.net]
	//   [dhcp-option] [DOMAIN] [example.com]
	//   [dhcp-option] [DOMAIN] [foo1.com foo2.com foo3.com]
	//   [dhcp-option] [DOMAIN] [bar1.com] [bar2.com] [bar3.com]
	unsigned int flags = 0;
	OptionList::IndexMap::const_iterator dopt = opt.map().find("dhcp-option"); // DIRECTIVE
	if (dopt != opt.map().end())
	  {
	    for (OptionList::IndexList::const_iterator i = dopt->second.begin(); i != dopt->second.end(); ++i)
	      {
		const Option& o = opt[*i];
		try {
		  const std::string& type = o.get(1, 64);
		  if (type == "DNS")
		    {
		      o.exact_args(3);
		      const IP::Addr ip = IP::Addr::from_string(o.get(2, 256), "dns-server-ip");
		      if (!tb->tun_builder_add_dns_server(ip.to_string(),
							  ip.version() == IP::Addr::V6))
			throw tun_builder_dhcp_option_error("tun_builder_add_dns_server failed");
		      flags |= F_ADD_DNS;
		    }
		  else if (type == "DOMAIN")
		    {
		      o.min_args(3);
		      for (size_t j = 2; j < o.size(); ++j)
			{
			  typedef std::vector<std::string> strvec;
			  strvec v = Split::by_space<strvec, StandardLex, SpaceMatch, Split::NullLimit>(o.get(j, 256));
			  for (size_t k = 0; k < v.size(); ++k)
			    {
			      if (!tb->tun_builder_add_search_domain(v[k]))
				throw tun_builder_dhcp_option_error("tun_builder_add_search_domain failed");
			    }
			}
		    }
		  else if (!quiet)
		    OPENVPN_LOG("Unknown pushed DHCP option: " << o.render());
		}
		catch (const std::exception& e)
		  {
		    OPENVPN_LOG("Error parsing dhcp-option: " << o.render() << " : " << e.what());
		  }
	      }
	  }
	return flags;
      }

      static bool search_domains_exist(const OptionList& opt)
      {
	OptionList::IndexMap::const_iterator dopt = opt.map().find("dhcp-option"); // DIRECTIVE
	if (dopt != opt.map().end())
	  {
	    for (OptionList::IndexList::const_iterator i = dopt->second.begin(); i != dopt->second.end(); ++i)
	      {
		const Option& o = opt[*i];
		try {
		  const std::string& type = o.get(1, 64);
		  if (type == "DOMAIN")
		    return true;
		}
		catch (const std::exception& e)
		  {
		    OPENVPN_LOG("Error parsing dhcp-option: " << o.render() << " : " << e.what());
		  }
	      }
	  }
	return false;
      }

      static void add_google_dns(TunBuilderBase* tb)
      {
	if (!tb->tun_builder_add_dns_server("8.8.8.8", false)
	    || !tb->tun_builder_add_dns_server("8.8.4.4", false))
	  throw tun_builder_dhcp_option_error("tun_builder_add_dns_server failed for Google DNS");
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
