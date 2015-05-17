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

#ifndef OPENVPN_SERVER_VPNSERVNETBLOCK_H
#define OPENVPN_SERVER_VPNSERVNETBLOCK_H

#include <sstream>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/addr/route.hpp>
#include <openvpn/addr/range.hpp>

namespace openvpn {

  class VPNServerNetblock
  {
  public:
    OPENVPN_EXCEPTION(vpn_serv_netblock);

    struct Netblock
    {
      Netblock() : prefix_len(0) {}

      Netblock(const IP::Route& route)
      {
	if (!route.is_canonical())
	  throw vpn_serv_netblock("not canonical");
	const size_t extent = route.extent();
	if (extent < 4)
	  throw vpn_serv_netblock("need at least 4 addresses in netblock");
	net = route.addr;
	server_gw = net + 1;
	bcast = net + (extent - 1);
	clients = IP::Range(net + 2, extent - 3);
	prefix_len = route.prefix_len;
      }

      bool defined() const { return net.defined(); }

      IP::Addr netmask() const
      {
	return IP::Addr::netmask_from_prefix_len(net.version(), prefix_len);
      }

      std::string to_string() const
      {
	return '[' + net.to_string() + ','
	  + server_gw.to_string() + ','
	  + clients.to_string() + ','
	  + bcast.to_string() + ']';
      }

      IP::Addr net;
      IP::Addr server_gw;
      IP::Range clients;
      IP::Addr bcast;
      unsigned int prefix_len;
    };

    class PerThread
    {
      friend class VPNServerNetblock;

    public:
      const IP::Range& range4() const { return range4_; }

      bool range6_defined() const { return range6_.defined(); }
      const IP::Range& range6() const { return range6_; }

    private:
      IP::Range range4_;
      IP::Range range6_;
    };

    VPNServerNetblock(const OptionList& opt, const unsigned int n_threads)
    {
      // ifconfig
      {
	const Option& o = opt.get("server");
	const IP::Addr gw(o.get(1, 64), "server gateway");
	const IP::Addr nm(o.get(2, 64), "server netmask");
	IP::Route rt(gw, nm.prefix_len());
	if (rt.version() != IP::Addr::V4)
	  throw vpn_serv_netblock("server address is not IPv4");
	rt.force_canonical();
	snb4 = Netblock(rt);
	if (snb4.server_gw != gw)
	  throw vpn_serv_netblock("server local gateway must be first usable address of subnet");
      }

      // ifconfig-ipv6
      {
	const Option* o = opt.get_ptr("server-ipv6");
	if (o)
	  {
	    IP::Route rt(o->get(1, 64), "server-ipv6 network");
	    if (rt.version() != IP::Addr::V6)
	      throw vpn_serv_netblock("server-ipv6 network is not IPv6");
	    if (!rt.is_canonical())
	      throw vpn_serv_netblock("server-ipv6 network is not canonical");
	    snb6 = Netblock(rt);
	  }
      }

      if (n_threads)
	{
	  // IPv4 per-thread partition
	  {
	    IP::RangePartition rp(snb4.clients, n_threads);
	    IP::Range crange;
	    for (unsigned int i = 0; i < n_threads; ++i)
	      {
		if (!rp.next(crange))
		  throw vpn_serv_netblock("unexpected ServerNetblock4 partition fail");
		PerThread pt;
		pt.range4_ = crange;
		thr.push_back(pt);
	      }
	  }

	  // IPv6 per-thread partition
	  if (snb6.defined())
	    {
	      IP::RangePartition rp(snb6.clients, n_threads);
	      IP::Range crange;
	      for (unsigned int i = 0; i < n_threads; ++i)
		{
		  if (!rp.next(crange))
		    throw vpn_serv_netblock("unexpected ServerNetblock6 partition fail");
		  thr[i].range6_ = crange;
		}
	    }
	}
    }

    const Netblock& netblock4() const { return snb4; }
    const Netblock& netblock6() const { return snb6; }

    const size_t size() const { return thr.size(); }

    const PerThread& per_thread(const size_t index) const
    {
      return thr[index];
    }

    std::string to_string() const
    {
      std::ostringstream os;
      os << "IPv4: " << snb4.to_string() << std::endl;
      if (snb6.defined())
	os << "IPv6: " << snb6.to_string() << std::endl;
      for (size_t i = 0; i < thr.size(); ++i)
	{
	  const PerThread& pt = thr[i];
	  os << '[' << i << ']';
	  os << " v4=" << pt.range4().to_string();
	  if (pt.range6_defined())
	    os << " v6=" << pt.range6().to_string();
	  os << std::endl;
	}
      return os.str();
    }

  private:
    Netblock snb4;
    Netblock snb6;
    std::vector<PerThread> thr;
  };
}

#endif
