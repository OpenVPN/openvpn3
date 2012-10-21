//
//  capture.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TUN_BUILDER_CAPTURE_H
#define OPENVPN_TUN_BUILDER_CAPTURE_H

#include <string>
#include <sstream>

#include <openvpn/common/rc.hpp>
#include <openvpn/tun/builder/base.hpp>

namespace openvpn {
  struct TunBuilderCapture : public TunBuilderBase, public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<TunBuilderCapture> Ptr;

    virtual bool tun_builder_set_remote_address(const std::string& address, bool ipv6)
    {
      os << "set_remote_address addr=" << address << " ipv6=" << ipv6 << std::endl;
      return true;
    }

    virtual bool tun_builder_add_address(const std::string& address, int prefix_length, bool ipv6)
    {
      os << "add_address addr=" << address << "/" << prefix_length << " ipv6=" << ipv6 << std::endl;
      return true;
    }

    virtual bool tun_builder_reroute_gw(const std::string& server_address, bool server_address_ipv6, bool ipv6)
    {
      os << "reroute_gw serv_addr=" << server_address << " serv_ipv6=" << server_address_ipv6 << " ipv6=" << ipv6 << std::endl;
      return true;
    }

    virtual bool tun_builder_add_route(const std::string& address, int prefix_length, bool ipv6)
    {
      os << "add_route addr=" << address << "/" << prefix_length << " ipv6=" << ipv6 << std::endl;
      return true;
    }

    virtual bool tun_builder_exclude_route(const std::string& address, int prefix_length, bool ipv6)
    {
      os << "exclude_route addr=" << address << "/" << prefix_length << " ipv6=" << ipv6 << std::endl;
      return true;
    }

    virtual bool tun_builder_add_dns_server(const std::string& address, bool ipv6, bool reroute_dns)
    {
      os << "add_dns_server addr=" << address << " ipv6=" << ipv6 << " reroute_dns=" << reroute_dns << std::endl;
      return true;
    }

    virtual bool tun_builder_add_search_domain(const std::string& domain, bool reroute_dns)
    {
      os << "add_search_domain domain=" << domain << " reroute_dns=" << reroute_dns << std::endl;
      return true;
    }

    virtual bool tun_builder_set_mtu(int mtu)
    {
      os << "set_mtu mtu=" << mtu << std::endl;
      return true;
    }

    virtual bool tun_builder_set_session_name(const std::string& name)
    {
      os << "set_session_name name=" << name << std::endl;
      return true;
    }

    std::ostringstream os;
  };
}

#endif
