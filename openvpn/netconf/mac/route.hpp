//
//  route.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Deal with adding routes on Mac

#ifndef OPENVPN_NETCONF_MAC_ROUTE_H
#define OPENVPN_NETCONF_MAC_ROUTE_H

#include <cstring>
#include <string>
#include <sstream>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/netconf/mac/gwv4.hpp>
#include <openvpn/client/rgopt.hpp>

namespace openvpn {

  class RouteListMac : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<RouteListMac> Ptr;

    OPENVPN_EXCEPTION(route_error);

    RouteListMac(const OptionList& opt, const IP::Addr& server_addr_arg)
      : stopped(false), did_redirect_gw(false), server_addr(server_addr_arg)
    {
      local_gateway = get_default_gateway_v4();

      // get route-gateway
      {
	const Option& o = opt.get("route-gateway");
	o.exact_args(2);
	route_gateway = IP::Addr::from_string(o.get(1, 256), "route-gateway");
      }

      // do redirect-gateway
      rg_flags.init(opt);
      if (rg_flags.redirect_gateway_ipv4_enabled()) // fixme ipv6
	{
	  add_del_reroute_gw_v4(true);
	  did_redirect_gw = true;
	}
      else
	{
	  OptionList::IndexMap::const_iterator dopt = opt.map().find("route");
	  if (dopt != opt.map().end())
	    {
	      for (OptionList::IndexList::const_iterator i = dopt->second.begin(); i != dopt->second.end(); ++i)
		{
		  const Option& o = opt[*i];
		  try {
		    o.min_args(2);
		    if (o.size() >= 4 && o.ref(3) != "vpn_gateway")
		      throw route_error("only tunnel routes supported");
		    const IP::AddrMaskPair pair = IP::AddrMaskPair::from_string(o.get(1, 256), o.get_optional(2, 256), "route");
		    if (!pair.is_canonical())
		      throw route_error("route is not canonical");
		    add_del_route(true, pair.addr, pair.netmask, route_gateway);
		  }
		  catch (const std::exception& e)
		    {
		      OPENVPN_THROW(route_error, "error parsing received route: " << o.render(Option::RENDER_TRUNC_64|Option::RENDER_BRACKET) << " : " << e.what());
		    }
		}
	    }
	}
    }

    void stop()
    {
      if (!stopped)
	{
	  if (did_redirect_gw)
	    {
	      add_del_reroute_gw_v4(false);
	      did_redirect_gw = false;
	    }
	  stopped = true;
	}
    }

    virtual ~RouteListMac()
    {
      stop();
    }

  private:
    static const IP::Addr& get_default_gateway_v4()
    {
      MacGatewayInfoV4 gw; // fixme: handle IPv6
      return gw.gateway_addr();
    }

    void add_del_reroute_gw_v4(const bool add)
    {
      const IP::Addr a_255_255_255_255 = IP::Addr::from_string("255.255.255.255");
      const IP::Addr a_0_0_0_0 = IP::Addr::from_string("0.0.0.0");
      const IP::Addr a_128_0_0_0 = IP::Addr::from_string("128.0.0.0");

      add_del_route(add, server_addr, a_255_255_255_255, local_gateway);
      add_del_route(add, a_0_0_0_0, a_128_0_0_0, route_gateway);
      add_del_route(add, a_128_0_0_0, a_128_0_0_0, route_gateway);
    }

    int add_del_route(const bool add,
		      const IP::Addr& net,
		      const IP::Addr& mask,
		      const IP::Addr& gw)
    {
      Argv argv;
      argv.push_back("/sbin/route");
      if (add)
	argv.push_back("add");
      else
	argv.push_back("delete");
      argv.push_back("-net");
      argv.push_back(net.to_string());
      argv.push_back(gw.to_string());
      argv.push_back(mask.to_string());
      OPENVPN_LOG(argv.to_string());
      return system_cmd(argv[0], argv);
    }

    bool stopped;
    RedirectGatewayFlags rg_flags;
    bool did_redirect_gw;
    IP::Addr server_addr;
    IP::Addr route_gateway;
    IP::Addr local_gateway;
  };

} // namespace openvpn

#endif // OPENVPN_NETCONF_MAC_ROUTE_H
