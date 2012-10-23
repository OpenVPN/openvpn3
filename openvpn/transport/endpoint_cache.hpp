//
//  endpoint_cache.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TRANSPORT_ENDPOINT_CACHE_H
#define OPENVPN_TRANSPORT_ENDPOINT_CACHE_H

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/addr/ip.hpp>

namespace openvpn {

  class EndpointCache : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<EndpointCache> Ptr;

    template <class EP>
    bool get_endpoint(const std::string& host, const std::string& port, EP& server_endpoint) const
    {
      if (host == name && addr.defined())
	{
	  //OPENVPN_LOG("***** EndpointCache cache hit " << host << ':' << port << " -> " << addr);
	  server_endpoint.address(addr.to_asio());
	  server_endpoint.port(types<unsigned int>::parse(port));
	  return true;
	}
      else
	{
	  //OPENVPN_LOG("***** EndpointCache cache miss " << host << ':' << port);
	  return false;
	}
    }

    template <class EP>
    void set_endpoint(const std::string& host, const EP& server_endpoint)
    {
      name = host;
      addr = IP::Addr::from_asio(server_endpoint.address());
      //OPENVPN_LOG("***** EndpointCache set " << host << " -> " << addr);
    }

    bool has_endpoint(const std::string& host) const
    {
      return host == name && addr.defined();
    }

    bool defined() const
    {
      return addr.defined();
    }

    void invalidate()
    {
      name = "";
      addr.reset();
    }

  private:
    std::string name;
    IP::Addr addr;
  };

} // namespace openvpn

#endif // OPENVPN_TRANSPORT_ENDPOINT_CACHE_H
