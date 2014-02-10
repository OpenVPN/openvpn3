//
//  base.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TUN_BUILDER_BASE_H
#define OPENVPN_TUN_BUILDER_BASE_H

#include <string>

namespace openvpn {
  class TunBuilderBase
  {
  public:
    // Tun builder methods, loosely based on the Android VpnService.Builder
    // abstraction.  These methods comprise an abstraction layer that
    // allows the OpenVPN C++ core to call out to external methods for
    // establishing the tunnel, adding routes, etc.

    // All methods returning bool use the return
    // value to indicate success (true) or fail (false).
    // tun_builder_new() should be called first, then arbitrary setter methods,
    // and finally tun_builder_establish to return the socket descriptor
    // for the session.  IP addresses are pre-validated before being passed to
    // these methods.
    // This interface is based on Android's VpnService.Builder.

    // Callback to construct a new tun builder
    // Should be called first.
    virtual bool tun_builder_new()
    {
      return false;
    }

    // Callback to set address of remote server
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_remote_address(const std::string& address, bool ipv6)
    {
      return false;
    }

    // Callback to add network address to VPN interface
    // May be called more than once per tun_builder session
    virtual bool tun_builder_add_address(const std::string& address,
					 int prefix_length,
					 bool ipv6,
					 bool net30)
    {
      return false;
    }

    // Callback to reroute default gateway to VPN interface.
    // server_address is provided so that the implementation may exclude
    // it from the default route.
    // server_address_ipv6 is true if server_address is an IPv6 address.
    // ipv4 is true if the default route to be added should be IPv4.
    // ipv6 is true if the default route to be added should be IPv6.
    // flags are defined in RedirectGatewayFlags
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_reroute_gw(const std::string& server_address,
					bool server_address_ipv6,
					bool ipv4,
					bool ipv6,
					unsigned int flags)
    {
      return false;
    }

    // Callback to add route to VPN interface
    // May be called more than once per tun_builder session
    virtual bool tun_builder_add_route(const std::string& address,
				       int prefix_length,
				       bool ipv6)
    {
      return false;
    }

    // Callback to exclude route from VPN interface
    // May be called more than once per tun_builder session
    virtual bool tun_builder_exclude_route(const std::string& address,
					   int prefix_length,
					   bool ipv6)
    {
      return false;
    }

    // Callback to add DNS server to VPN interface
    // May be called more than once per tun_builder session
    // If reroute_dns is true, all DNS traffic should be routed over the
    // tunnel, while if false, only DNS traffic that matches an added search
    // domain should be routed.
    // Guaranteed to be called after tun_builder_reroute_gw.
    virtual bool tun_builder_add_dns_server(const std::string& address, bool ipv6)
    {
      return false;
    }

    // Callback to add search domain to DNS resolver
    // May be called more than once per tun_builder session
    // See tun_builder_add_dns_server above for description of
    // reroute_dns parameter.
    // Guaranteed to be called after tun_builder_reroute_gw.
    virtual bool tun_builder_add_search_domain(const std::string& domain)
    {
      return false;
    }

    // Callback to set MTU of the VPN interface
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_mtu(int mtu)
    {
      return false;
    }

    // Callback to set the session name
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_session_name(const std::string& name)
    {
      return false;
    }

    // Callback to add a host which should bypass the proxy
    // May be called more than once per tun_builder session
    virtual bool tun_builder_add_proxy_bypass(const std::string& bypass_host)
    {
      return false;
    }

    // Callback to set the proxy "Auto Config URL"
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_proxy_auto_config_url(const std::string& url)
    {
      return false;
    }

    // Callback to set the HTTP proxy
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_proxy_http(const std::string& host, int port)
    {
      return false;
    }

    // Callback to set the HTTPS proxy
    // Never called more than once per tun_builder session.
    virtual bool tun_builder_set_proxy_https(const std::string& host, int port)
    {
      return false;
    }

    // Callback to establish the VPN tunnel, returning a file descriptor
    // to the tunnel, which the caller will henceforth own.  Returns -1
    // if the tunnel could not be established.
    // Always called last after tun_builder session has been configured.
    virtual int tun_builder_establish()
    {
      return -1;
    }

    // Called just before tunnel socket is closed
    virtual void tun_builder_teardown() {}

    virtual ~TunBuilderBase() {}
  };
}

#endif
