//
//  tunnull.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Null tun interface object, intended for testing.

#ifndef OPENVPN_TUN_CLIENT_TUNNULL_H
#define OPENVPN_TUN_CLIENT_TUNNULL_H

#include <openvpn/tun/client/tunbase.hpp>

namespace openvpn {
  namespace TunNull {

    class ClientConfig : public TunClientFactory
    {
    public:
      typedef boost::intrusive_ptr<ClientConfig> Ptr;

      Frame::Ptr frame;
      SessionStats::Ptr stats;

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_client_obj(boost::asio::io_service& io_service,
					    TunClientParent& parent);
    private:
      ClientConfig() {}
    };

    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor

    public:
      virtual void client_start(const OptionList& opt, TransportClient& transcli)
      {
	// signal that we are "connected"
	parent.tun_connected();
      }

      virtual bool tun_send(BufferAllocated& buf)
      {
	config->stats->inc_stat(SessionStats::TUN_BYTES_OUT, buf.size());
	config->stats->inc_stat(SessionStats::TUN_PACKETS_OUT, 1);
	return true;
      }

      virtual std::string tun_name() const
      {
	return "TUN_NULL";
      }

      virtual std::string vpn_ip4() const
      {
	return "";
      }

      virtual std::string vpn_ip6() const
      {
	return "";
      }

      virtual void stop() {}

    private:
      Client(boost::asio::io_service& io_service_arg,
	     ClientConfig* config_arg,
	     TunClientParent& parent_arg)
	:  io_service(io_service_arg),
	   config(config_arg),
	   parent(parent_arg)
      {
      }

      boost::asio::io_service& io_service;
      ClientConfig::Ptr config;
      TunClientParent& parent;
    };

    inline TunClient::Ptr ClientConfig::new_client_obj(boost::asio::io_service& io_service,
						       TunClientParent& parent)
    {
      return TunClient::Ptr(new Client(io_service, this, parent));
    }

  }
} // namespace openvpn

#endif // OPENVPN_TUN_CLIENT_TUNNULL_H
