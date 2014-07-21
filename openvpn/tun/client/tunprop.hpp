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

// Process tun interface properties.

#ifndef OPENVPN_TUN_CLIENT_TUNPROP_H
#define OPENVPN_TUN_CLIENT_TUNPROP_H

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/port.hpp>
#include <openvpn/tun/builder/base.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/addrpair.hpp>
#include <openvpn/client/rgopt.hpp>

namespace openvpn {
  class TunProp {
    // IP version flags
    enum {
      F_IPv4=(1<<0),
      F_IPv6=(1<<1),
    };

    // add_dns flags
    enum {
      F_ADD_DNS=(1<<0),
    };

    // render option flags
    enum {
      OPT_RENDER_FLAGS = Option::RENDER_TRUNC_64 | Option::RENDER_BRACKET
    };

  public:
    OPENVPN_EXCEPTION(tun_prop_error);
    OPENVPN_EXCEPTION(tun_prop_route_error);
    OPENVPN_EXCEPTION(tun_prop_dhcp_option_error);

    struct Config
    {
      Config() : mtu(0), google_dns_fallback(false) {}

      std::string session_name;
      int mtu;
      bool google_dns_fallback;
    };

    struct State : public RC<thread_unsafe_refcount>
    {
      typedef boost::intrusive_ptr<State> Ptr;

      std::string iface_name;
      IP::Addr vpn_ip4_addr;
      IP::Addr vpn_ip6_addr;
    };

    static void configure_builder(TunBuilderBase* tb,
				  State* state,
				  SessionStats* stats,
				  const IP::Addr& server_addr,
				  const Config& config,
				  const OptionList& opt,
				  const bool quiet)
    {
      // do ifconfig
      const unsigned int ip_ver_flags = tun_ifconfig(tb, state, opt);

      // add routes
      const unsigned int reroute_gw_ver_flags = add_routes(tb, opt, server_addr, ip_ver_flags, quiet);

      // add DNS servers and domain prefixes
      const unsigned int dhcp_option_flags = add_dhcp_options(tb, opt, quiet);

      // Block IPv6?
      tb->tun_builder_set_block_ipv6(opt.exists("block-ipv6") && !(ip_ver_flags & F_IPv6));

      // DNS fallback
      if ((reroute_gw_ver_flags & F_IPv4) && !(dhcp_option_flags & F_ADD_DNS))
	{
	  if (config.google_dns_fallback)
	    {
	      if (!quiet)
		OPENVPN_LOG("Google DNS fallback enabled");
	      add_google_dns(tb);
	    }
	  else if (stats)
	    stats->error(Error::REROUTE_GW_NO_DNS);
	}

      // set remote server address
      if (!tb->tun_builder_set_remote_address(server_addr.to_string(),
					      server_addr.version() == IP::Addr::V6))
	throw tun_prop_error("tun_builder_set_remote_address failed");

      // set MTU
      if (config.mtu)
	{
	  if (!tb->tun_builder_set_mtu(config.mtu))
	    throw tun_prop_error("tun_builder_set_mtu failed");
	}

      // set session name
      if (!config.session_name.empty())
	{
	  if (!tb->tun_builder_set_session_name(config.session_name))
	    throw tun_prop_error("tun_builder_set_session_name failed");
	}
    }

  private:

    static std::string route_gateway(const OptionList& opt)
    {
      std::string ret;
      const Option* o = opt.get_ptr("route-gateway"); // DIRECTIVE
      if (o)
	{
	  const IP::Addr gateway = IP::Addr::from_string(o->get(1, 256), "route-gateway");
	  if (gateway.version() != IP::Addr::V4)
	    throw tun_prop_error("route-gateway is not IPv4 (IPv6 route-gateway is passed with ifconfig-ipv6 directive)");
	  ret = gateway.to_string();
	}
      return ret;
    }

    static unsigned int tun_ifconfig(TunBuilderBase* tb, State* state, const OptionList& opt)
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
		  throw tun_prop_error("ifconfig address is not IPv4 (topology subnet)");
		if (!tb->tun_builder_add_address(pair.addr.to_string(),
						 pair.netmask.prefix_len(),
						 route_gateway(opt),
						 false,  // IPv6
						 false)) // net30
		  throw tun_prop_error("tun_builder_add_address IPv4 failed (topology subnet)");
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
		  throw tun_prop_error("ifconfig address is not IPv4 (topology net30)");
		if ((local & netmask) != (remote & netmask))
		  throw tun_prop_error("ifconfig addresses are not in the same /30 subnet (topology net30)");
		if (!tb->tun_builder_add_address(local.to_string(),
						 netmask.prefix_len(),
						 remote.to_string(),
						 false, // IPv6
						 true)) // net30
		  throw tun_prop_error("tun_builder_add_address IPv4 failed (topology net30)");
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
	    // We don't check topology setting here since it doesn't really affect IPv6
	    const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string(o->get(1, 256), "ifconfig-ipv6");
	    if (pair.version() != IP::Addr::V6)
	      throw tun_prop_error("ifconfig-ipv6 address is not IPv6");
	    std::string gateway_str;
	    if (o->size() >= 3)
	      {
		const IP::Addr gateway = IP::Addr::from_string(o->get(2, 256), "ifconfig-ipv6");
		if (gateway.version() != IP::Addr::V6)
		  throw tun_prop_error("ifconfig-ipv6 gateway is not IPv6");
		gateway_str = gateway.to_string();
	      }
	    if (!tb->tun_builder_add_address(pair.addr.to_string(),
					     pair.netmask.prefix_len(),
					     gateway_str,
					     true,   // IPv6
					     false)) // net30
	      throw tun_prop_error("tun_builder_add_address IPv6 failed");
	    if (state)
	      state->vpn_ip6_addr = pair.addr;
	    ip_ver_flags |= F_IPv6;
	  }

	if (!ip_ver_flags)
	  throw tun_prop_error("one of ifconfig or ifconfig-ipv6 must be specified");
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
	    throw tun_prop_route_error("tun_builder_add_route failed");
	}
      else
	{
	  if (!tb->tun_builder_exclude_route(address, prefix_length, ipv6))
	    throw tun_prop_route_error("tun_builder_exclude_route failed");
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
	    throw tun_prop_route_error("route destinations other than vpn_gateway or net_gateway are not supported");
	}
      else
	return true;
    }

    static unsigned int add_routes(TunBuilderBase* tb,
				   const OptionList& opt,
				   const IP::Addr& server_addr,
				   const unsigned int ip_ver_flags,
				   const bool quiet)
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
      if (!tb->tun_builder_reroute_gw((reroute_gw_ver_flags & F_IPv4) ? true : false,
				      (reroute_gw_ver_flags & F_IPv6) ? true : false,
				      rg_flags()))
	throw tun_prop_route_error("tun_builder_reroute_gw for redirect-gateway failed");

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
		      throw tun_prop_error("route is not canonical");
		    if (pair.version() != IP::Addr::V4)
		      throw tun_prop_error("route is not IPv4");
		    const bool add = route_target(o, 3);
		    if (!(reroute_gw_ver_flags & F_IPv4) || !add)
		      add_exclude_route(tb, add, pair.addr.to_string(), pair.netmask.prefix_len(), false);
		  }
		  catch (const std::exception& e)
		    {
		      if (!quiet)
			OPENVPN_LOG("Error parsing IPv4 route: " << o.render(OPT_RENDER_FLAGS) << " : " << e.what());
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
		      throw tun_prop_error("route is not canonical");
		    if (pair.version() != IP::Addr::V6)
		      throw tun_prop_error("route is not IPv6");
		    const bool add = route_target(o, 2);
		    if (!(reroute_gw_ver_flags & F_IPv6) || !add)
		      add_exclude_route(tb, add, pair.addr.to_string(), pair.netmask.prefix_len(), true);
		  }
		  catch (const std::exception& e)
		    {
		      if (!quiet)
			OPENVPN_LOG("Error parsing IPv6 route: " << o.render(OPT_RENDER_FLAGS) << " : " << e.what());
		    }
		}
	    }
	}
      return reroute_gw_ver_flags;
    }

    static unsigned int add_dhcp_options(TunBuilderBase* tb, const OptionList& opt, const bool quiet)
    {
      // Example:
      //   [dhcp-option] [DNS] [172.16.0.23]
      //   [dhcp-option] [WINS] [172.16.0.23]
      //   [dhcp-option] [DOMAIN] [openvpn.net]
      //   [dhcp-option] [DOMAIN] [example.com]
      //   [dhcp-option] [DOMAIN] [foo1.com foo2.com foo3.com ...]
      //   [dhcp-option] [DOMAIN] [bar1.com] [bar2.com] [bar3.com] ...
      //   [dhcp-option] [PROXY_HTTP] [foo.bar.gov] [1234]
      //   [dhcp-option] [PROXY_HTTPS] [foo.bar.gov] [1234]
      //   [dhcp-option] [PROXY_BYPASS] [server1] [server2] ...
      //   [dhcp-option] [PROXY_AUTO_CONFIG_URL] [http://...]
      unsigned int flags = 0;
      OptionList::IndexMap::const_iterator dopt = opt.map().find("dhcp-option"); // DIRECTIVE
      if (dopt != opt.map().end())
	{
	  std::string auto_config_url;
	  std::string http_host;
	  unsigned int http_port;
	  std::string https_host;
	  unsigned int https_port;
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
		      throw tun_prop_dhcp_option_error("tun_builder_add_dns_server failed");
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
			      throw tun_prop_dhcp_option_error("tun_builder_add_search_domain failed");
			  }
		      }
		  }
		else if (type == "PROXY_BYPASS")
		  {
		    o.min_args(3);
		    for (size_t j = 2; j < o.size(); ++j)
		      {
			typedef std::vector<std::string> strvec;
			strvec v = Split::by_space<strvec, StandardLex, SpaceMatch, Split::NullLimit>(o.get(j, 256));
			for (size_t k = 0; k < v.size(); ++k)
			  {
			    if (!tb->tun_builder_add_proxy_bypass(v[k]))
			      throw tun_prop_dhcp_option_error("tun_builder_add_proxy_bypass");
			  }
		      }
		  }
		else if (type == "PROXY_AUTO_CONFIG_URL")
		  {
		    o.exact_args(3);
		    auto_config_url = o.get(2, 256);
		  }
		else if (type == "PROXY_HTTP")
		  {
		    o.exact_args(4);
		    http_host = o.get(2, 256);
		    validate_port(o.get(3, 256), "PROXY_HTTP port", &http_port);
		  }
		else if (type == "PROXY_HTTPS")
		  {
		    o.exact_args(4);
		    https_host = o.get(2, 256);
		    validate_port(o.get(3, 256), "PROXY_HTTPS port", &https_port);
		  }
		else if (type == "WINS")
		  {
		    o.exact_args(3);
		    const IP::Addr ip = IP::Addr::from_string(o.get(2, 256), "wins-server-ip");
		    if (ip.version() != IP::Addr::V4)
		      throw tun_prop_dhcp_option_error("WINS addresses must be IPv4");
		    if (!tb->tun_builder_add_wins_server(ip.to_string()))
		      throw tun_prop_dhcp_option_error("tun_builder_add_wins_server failed");
		  }
		else if (!quiet)
		  OPENVPN_LOG("Unknown pushed DHCP option: " << o.render(OPT_RENDER_FLAGS));
	      }
	      catch (const std::exception& e)
		{
		  if (!quiet)
		    OPENVPN_LOG("Error parsing dhcp-option: " << o.render(OPT_RENDER_FLAGS) << " : " << e.what());
		}
	    }
	  try {
	    if (!http_host.empty())
	      {
		if (!tb->tun_builder_set_proxy_http(http_host, http_port))
		  throw tun_prop_dhcp_option_error("tun_builder_set_proxy_http");
	      }
	    if (!https_host.empty())
	      {
		if (!tb->tun_builder_set_proxy_https(https_host, https_port))
		  throw tun_prop_dhcp_option_error("tun_builder_set_proxy_https");
	      }
	    if (!auto_config_url.empty())
	      {
		if (!tb->tun_builder_set_proxy_auto_config_url(auto_config_url))
		  throw tun_prop_dhcp_option_error("tun_builder_set_proxy_auto_config_url");
	      }
	  }
	  catch (const std::exception& e)
	    {
	      if (!quiet)
		OPENVPN_LOG("Error setting dhcp-option for proxy: " << e.what());
	    }
	}
      return flags;
    }

    static bool search_domains_exist(const OptionList& opt, const bool quiet)
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
		  if (!quiet)
		    OPENVPN_LOG("Error parsing dhcp-option: " << o.render(OPT_RENDER_FLAGS) << " : " << e.what());
		}
	    }
	}
      return false;
    }

    static void add_google_dns(TunBuilderBase* tb)
    {
      if (!tb->tun_builder_add_dns_server("8.8.8.8", false)
	  || !tb->tun_builder_add_dns_server("8.8.4.4", false))
	throw tun_prop_dhcp_option_error("tun_builder_add_dns_server failed for Google DNS");
    }
  };
} // namespace openvpn

#endif // OPENVPN_TUN_CLIENT_TUNPROP_H
