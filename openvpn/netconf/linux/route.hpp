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

// Deal with adding routes on Linux

#ifndef OPENVPN_NETCONF_LINUX_ROUTE_H
#define OPENVPN_NETCONF_LINUX_ROUTE_H

#include <string>
#include <sstream>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/client/rgopt.hpp>

namespace openvpn {

  class RouteListLinux : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<RouteListLinux> Ptr;

    OPENVPN_EXCEPTION(route_error);

    RouteListLinux(const OptionList& opt, const IP::Addr& server_addr_arg)
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

    virtual ~RouteListLinux()
    {
      stop();
    }

  private:
    static IP::Addr get_default_gateway_v4()
    {
      typedef std::vector<std::string> strvec;
      const std::string proc_net_route = read_text_simple("/proc/net/route");
      SplitLines in(proc_net_route, 0);
      std::string best_gw;
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
      throw route_error("can't determine default gateway");
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
	argv.push_back("del");
      argv.push_back("-net");
      argv.push_back(net.to_string());
      argv.push_back("netmask");
      argv.push_back(mask.to_string());
      argv.push_back("gw");
      argv.push_back(gw.to_string());
      OPENVPN_LOG(argv.to_string());
      return system_cmd(argv[0], argv);
    }

    static IP::Addr cvt_pnr_ip_v4(const std::string& hexaddr)
    {
      BufferAllocated v(4, BufferAllocated::CONSTRUCT_ZERO);
      parse_hex(v, hexaddr);
      if (v.size() != 4)
	throw route_error("bad hex address");
      IPv4::Addr ret = IPv4::Addr::from_bytes(v.data());
      return IP::Addr::from_ipv4(ret);
    }

    bool stopped;
    RedirectGatewayFlags rg_flags;
    bool did_redirect_gw;
    IP::Addr server_addr;
    IP::Addr route_gateway;
    IP::Addr local_gateway;
  };

} // namespace openvpn

#endif // OPENVPN_NETCONF_LINUX_ROUTE_H
