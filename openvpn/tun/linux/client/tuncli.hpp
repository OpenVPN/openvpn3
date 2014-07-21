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

// Client tun interface for Linux.

#ifndef OPENVPN_TUN_LINUX_CLIENT_TUNCLI_H
#define OPENVPN_TUN_LINUX_CLIENT_TUNCLI_H

#include <openvpn/tun/linux/tun.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/netconf/linux/route.hpp>

namespace openvpn {
  namespace TunLinux {

    class ClientConfig : public TunClientFactory
    {
    public:
      typedef boost::intrusive_ptr<ClientConfig> Ptr;

      std::string name;
      bool ipv6;
      Layer layer;
      int txqueuelen;
      unsigned int mtu;

      int n_parallel;
      Frame::Ptr frame;
      SessionStats::Ptr stats;

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TunClient::Ptr new_client_obj(boost::asio::io_service& io_service,
					    TunClientParent& parent);
    private:
      ClientConfig()
	: ipv6(false), txqueuelen(200), mtu(1500), n_parallel(8) {}
    };

    class Client : public TunClient
    {
      friend class ClientConfig;  // calls constructor
      friend class TunIO<Client*, PacketFrom, boost::asio::posix::stream_descriptor>;  // calls tun_read_handler

      typedef Tun<Client*> TunImpl;

    public:
      virtual void client_start(const OptionList& opt, TransportClient& transcli)
      {
	if (!impl)
	  {
	    halt = false;
	    try {
	      // start tun
	      impl.reset(new TunImpl(io_service,
				     this,
				     config->frame,
				     config->stats,
				     config->name,
				     config->ipv6,
				     config->layer,
				     config->txqueuelen
				     ));
	      impl->start(config->n_parallel);

	      // do ifconfig
	      parent.tun_pre_tun_config();
	      vpn_ip_addr = impl->ifconfig(opt, config->mtu);

	      // add routes
	      parent.tun_pre_route_config();
	      route_list.reset(new RouteListLinux(opt, transcli.server_endpoint_addr()));

	      // signal that we are connected
	      parent.tun_connected();
	    }
	    catch (const std::exception& e)
	      {
		stop();
		parent.tun_error(Error::TUN_SETUP_FAILED, e.what());
	      }
	  }
      }

      virtual bool tun_send(BufferAllocated& buf)
      {
	return send(buf);
      }

      virtual std::string tun_name() const
      {
	if (impl)
	  return impl->name();
	else
	  return "UNDEF_TUN";
      }

      virtual std::string vpn_ip4() const
      {
	return vpn_ip_addr;
      }

      virtual std::string vpn_ip6() const // fixme ipv6
      {
	return "";
      }

      virtual void stop() { stop_(); }
      virtual ~Client() { stop_(); }

    private:
      Client(boost::asio::io_service& io_service_arg,
	     ClientConfig* config_arg,
	     TunClientParent& parent_arg)
	:  io_service(io_service_arg),
	   config(config_arg),
	   parent(parent_arg),
	   halt(false)
      {
      }

      bool send(Buffer& buf)
      {
	if (impl)
	  return impl->write(buf);
	else
	  return false;
      }

      void tun_read_handler(PacketFrom::SPtr& pfp) // called by TunImpl
      {
	parent.tun_recv(pfp->buf);
      }

      void tun_error_handler(const Error::Type errtype, // called by TunImpl
			     const boost::system::error_code* error)
      {
      }

      void stop_()
      {
	if (!halt)
	  {
	    halt = true;

	    // remove added routes
	    if (route_list)
	      route_list->stop();

	    // stop tun
	    if (impl)
	      impl->stop();
	  }
      }

      boost::asio::io_service& io_service;
      ClientConfig::Ptr config;
      TunClientParent& parent;
      TunImpl::Ptr impl;
      RouteListLinux::Ptr route_list;
      std::string vpn_ip_addr;
      bool halt;
    };

    inline TunClient::Ptr ClientConfig::new_client_obj(boost::asio::io_service& io_service,
						       TunClientParent& parent)
    {
      return TunClient::Ptr(new Client(io_service, this, parent));
    }

  }
} // namespace openvpn

#endif // OPENVPN_TUN_LINUX_CLIENT_TUNCLI_H
