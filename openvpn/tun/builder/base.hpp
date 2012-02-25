#ifndef OPENVPN_TUN_BUILDER_BASE_H
#define OPENVPN_TUN_BUILDER_BASE_H

#include <string>

namespace openvpn {
  class TunBuilderBase
  {
  public:
    // Tun builder methods.  These methods comprise an abstraction layer that
    // allows the OpenVPN C++ core to call out to external methods for
    // establishing the tunnel, adding routes, etc.

    // All methods returning bool use the return
    // value to indicate success (true) or fail (false).
    // tun_builder_new() should be called first, then arbitrary setter methods,
    // and finally tun_builder_establish to return the socket descriptor
    // for the session.
    // This interface is based on Android's VpnService.Builder.

    // Callback to construct a new tun builder
    virtual bool tun_builder_new()
    {
      return false;
    }

    // Callback to to add network address to VPN interface
    virtual bool tun_builder_add_address(const std::string& address, int prefix_length)
    {
      return false;
    }

    // Callback to add route to VPN interface
    virtual bool tun_builder_add_route(const std::string& address, int prefix_length)
    {
      return false;
    }

    // Callback to add DNS server to VPN interface
    virtual bool tun_builder_add_dns_server(const std::string& address)
    {
      return false;
    }

    // Callback to add search domain to DNS resolver
    virtual bool tun_builder_add_search_domain(const std::string& domain)
    {
      return false;
    }

    // Callback to set MTU of the VPN interface
    virtual bool tun_builder_set_mtu(int mtu)
    {
      return false;
    }

    // Callback to set the session name
    virtual bool tun_builder_set_session_name(const std::string& name)
    {
      return false;
    }

    // Callback to establish the VPN tunnel, returning a file descriptor
    // to the tunnel, which the caller will henceforth own.  Returns -1
    // if the tunnel could not be established.
    virtual int tun_builder_establish()
    {
      return -1;
    }
  };
}

#endif
