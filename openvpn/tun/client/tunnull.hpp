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
