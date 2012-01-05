#ifndef OPENVPN_NETCONF_MAC_ROUTE_H
#define OPENVPN_NETCONF_MAC_ROUTE_H

#include <string>
#include <sstream>

#include <boost/lexical_cast.hpp>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/process.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/split.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/log/log.hpp>

namespace openvpn {

  class RouteListMac : public RC<thread_unsafe_refcount>
  {
    // redirect-gateway flags
    enum {
      RG_ENABLE      = (1<<0),
      RG_REROUTE_GW  = (1<<1),
      RG_LOCAL       = (1<<2),
      RG_AUTO_LOCAL  = (1<<3),
      RG_DEF1        = (1<<4),
      RG_BYPASS_DHCP = (1<<5),
      RG_BYPASS_DNS  = (1<<6),
      RG_BLOCK_LOCAL = (1<<7),
    };

  public:
    typedef boost::intrusive_ptr<RouteListMac> Ptr;

    OPENVPN_EXCEPTION(route_error);

    RouteListMac(const OptionList& opt, const boost::asio::ip::address& server_addr_arg)
      : stopped(false), rg_flags(0), did_redirect_gw(false), server_addr(server_addr_arg)
    {
      local_gateway = get_default_gateway();

      // get route-gateway
      {
	const Option& o = opt.get("route-gateway");
	o.exact_args(2);
	route_gateway = validate_ip_address("route-gateway", o[1]);
      }

      // do redirect-gateway
      {
	OptionList::IndexMap::const_iterator e = opt.map().find("redirect-gateway");
	if (e != opt.map().end())
	  {
	    const OptionList::IndexList& idx = e->second;
	    for (OptionList::IndexList::const_iterator i = idx.begin(); i != idx.end(); i++)
	      {
		const Option& o = opt[*i];
		for (size_t j = 1; j < o.size(); ++j)
		  {
		    const std::string& f = o[j];
		    rg_flags |= RG_ENABLE;
		    if (f == "def1")
		      rg_flags |= RG_DEF1;
		  }
	      }
	  }
	if (rg_flags & RG_ENABLE)
	  {
	    add_del_route(true, server_addr.to_string(), "255.255.255.255", local_gateway);
	    add_del_route(true, "0.0.0.0", "128.0.0.0", route_gateway);
	    add_del_route(true, "128.0.0.0", "128.0.0.0", route_gateway);
	    did_redirect_gw = true;
	  }
      }
    }

    void stop()
    {
      if (!stopped)
	{
	  if (did_redirect_gw)
	    {
	      add_del_route(false, server_addr.to_string(), "255.255.255.255", local_gateway);
	      add_del_route(false, "0.0.0.0", "128.0.0.0", route_gateway);
	      add_del_route(false, "128.0.0.0", "128.0.0.0", route_gateway);
	      did_redirect_gw = false;
	    }
	  stopped = true;
	}
    }

    virtual ~RouteListMac()
    {
      stop();
    }

    static std::string get_default_gateway()
    {
      return "10.10.0.1"; // fixme
    }

  private:
    int add_del_route(const bool add,
		      const std::string& net,
		      const std::string& mask,
		      const std::string& gw)
    {
	std::ostringstream cmd;
	cmd << "/sbin/route";
	if (add)
	  cmd << " add";
	else
	  cmd << " delete";
	cmd << " -net " << net << ' ' << gw << ' ' << mask;
	const std::string cmd_str = cmd.str();
	OPENVPN_LOG(cmd_str);
	return ::system(cmd_str.c_str());
    }

    bool stopped;
    unsigned int rg_flags;
    bool did_redirect_gw;
    boost::asio::ip::address server_addr;
    std::string route_gateway;
    std::string local_gateway;
  };

} // namespace openvpn

#endif // OPENVPN_NETCONF_MAC_ROUTE_H
