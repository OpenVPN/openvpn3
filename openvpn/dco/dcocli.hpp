//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2020 OpenVPN Inc.
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

#pragma once

#include <vector>
#include <memory>
#include <sstream>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/to_string.hpp>
#include <openvpn/buffer/asiobuf.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/builder/capture.hpp>
#include <openvpn/tun/linux/client/tunmethods.hpp>
#include <openvpn/transport/dco.hpp>

#ifdef ENABLE_KOVPN
#include <openvpn/kovpn/kovpn.hpp>
#include <openvpn/kovpn/kostats.hpp>
#include <openvpn/kovpn/rps_xps.hpp>
#include <openvpn/kovpn/kodevtun.hpp>
#elif ENABLE_OVPNDCO
#include <openvpn/dco/key.hpp>
#include <openvpn/tun/linux/client/sitnl.hpp>
#include <openvpn/common/uniqueptr.hpp>
#include <openvpn/tun/linux/client/genl.hpp>
#include <openvpn/buffer/buffer.hpp>
#else
#error either ENABLE_KOVPN or ENABLE_OVPNDCO must be defined
#endif

#include <openvpn/dco/korekey.hpp>
#include <openvpn/dco/protowrapper.hpp>

// client-side DCO (Data Channel Offload) module for Linux/kovpn

namespace openvpn {
  namespace DCOTransport {

    OPENVPN_EXCEPTION(dco_error);

    class ClientConfig : public DCO,
			 public TransportClientFactory,
			 public TunClientFactory
    {
    public:
      typedef RCPtr<ClientConfig> Ptr;

      std::string dev_name;

      DCO::TransportConfig transport;
      DCO::TunConfig tun;

      unsigned int ping_restart_override = 0;

      virtual TunClientFactory::Ptr new_tun_factory(const DCO::TunConfig& conf, const OptionList& opt) override
      {
	tun = conf;

	// set a default MTU
	if (!tun.tun_prop.mtu)
	  tun.tun_prop.mtu = 1500;

	// parse "dev" option
	{
	  const Option* dev = opt.get_ptr("dev");
	  if (dev)
	    dev_name = dev->get(1, 64);
	  else
	    dev_name = "ovpnc";
	}

	// parse ping-restart-override
	ping_restart_override = opt.get_num<decltype(ping_restart_override)>("ping-restart-override", 1, ping_restart_override, 0, 3600);

	return TunClientFactory::Ptr(this);
      }

      virtual TransportClientFactory::Ptr new_transport_factory(const DCO::TransportConfig& conf) override
      {
	transport = conf;
	return TransportClientFactory::Ptr(this);
      }

      virtual TunClient::Ptr new_tun_client_obj(openvpn_io::io_context& io_context,
						TunClientParent& parent,
						TransportClient* transcli) override;

      virtual TransportClient::Ptr new_transport_client_obj(openvpn_io::io_context& io_context,
							    TransportClientParent* parent) override;

      static DCO::Ptr new_controller()
      {
	return new ClientConfig();
      }

    protected:
      ClientConfig() = default;
    };

    class Client : public TransportClient,
		   public TunClient,
		   public AsyncResolvableUDP
    {
      friend class ClientConfig;

      typedef RCPtr<Client> Ptr;

    public:
      // transport methods

      virtual bool transport_send_queue_empty() override
      {
	return false;
      }

      virtual bool transport_has_send_queue() override
      {
	return false;
      }

      virtual unsigned int transport_send_queue_size() override
      {
	return 0;
      }

      virtual void reset_align_adjust(const size_t align_adjust) override
      {
      }

      virtual void transport_stop_requeueing() override
      {
      }

      virtual void server_endpoint_info(std::string& host, std::string& port, std::string& proto, std::string& ip_addr) const override
      {
	host = server_host;
	port = server_port;
	const IP::Addr addr = server_endpoint_addr();
	proto = config->transport.protocol.is_tcp() ? "TCP" : "UDP";
	proto += addr.version_string();
	proto += "-DCO";
	ip_addr = addr.to_string();
      }

      virtual IP::Addr server_endpoint_addr() const override
      {
	if (proto)
	  return proto->server_endpoint_addr();
	else
	  return IP::Addr();
      }

      virtual Protocol transport_protocol() const override
      {
	switch (server_endpoint_addr().version())
	  {
	  case IP::Addr::V4:
	    return Protocol(Protocol::UDPv4);
	  case IP::Addr::V6:
	    return Protocol(Protocol::UDPv6);
	  default:
	    return Protocol();
	  }
      }

      virtual void stop() override
      {
	stop_();
      }

      // tun methods

      virtual void set_disconnect() override
      {
      }

      virtual bool tun_send(BufferAllocated& buf) override // return true if send succeeded
      {
	return false;
      }

      virtual std::string vpn_ip4() const override
      {
	if (state->vpn_ip4_addr.specified())
	  return state->vpn_ip4_addr.to_string();
	else
	  return "";
      }

      virtual std::string vpn_ip6() const override
      {
	if (state->vpn_ip6_addr.specified())
	  return state->vpn_ip6_addr.to_string();
	else
	  return "";
      }

      virtual std::string vpn_gw4() const override
      {
	if (state->vpn_ip4_gw.specified())
	  return state->vpn_ip4_gw.to_string();
	else
	  return "";
      }

      virtual std::string vpn_gw6() const override
      {
	if (state->vpn_ip6_gw.specified())
	  return state->vpn_ip6_gw.to_string();
	else
	  return "";
      }

    protected:
      Client(openvpn_io::io_context& io_context_arg,
	     ClientConfig* config_arg,
	     TransportClientParent* parent_arg)
	: AsyncResolvableUDP(io_context_arg),
	  io_context(io_context_arg),
	  halt(false),
	  state(new TunProp::State()),
	  config(config_arg),
	  transport_parent(parent_arg),
	  tun_parent(nullptr),
	  peer_id(-1)
      {
      }

      virtual void transport_reparent(TransportClientParent* parent_arg) override
      {
	transport_parent = parent_arg;
      }

      void transport_start_udp()
      {
	transport_start_impl(false);
      }

      void transport_start_tcp()
      {
	transport_start_impl(true);
      }

      void transport_start_impl(bool tcp)
      {
	if (tcp)
	  proto.reset(new TCP(io_context));
	else
	  proto.reset(new UDP(io_context));

	if (config->transport.remote_list->endpoint_available(&server_host, &server_port, nullptr))
	  {
	    start_connect();
	  }
	else
	  {
	    transport_parent->transport_pre_resolve();
	    async_resolve_name(server_host, server_port);
	  }
      }

      // called after DNS resolution has succeeded or failed
      void resolve_callback(const openvpn_io::error_code& error,
			    openvpn_io::ip::udp::resolver::results_type results) override
      {
	if (!halt)
	  {
	    if (!error)
	      {
		// save resolved endpoint list in remote_list
		config->transport.remote_list->set_endpoint_range(results);
		start_connect();
	      }
	    else
	      {
		std::ostringstream os;
		os << "DNS resolve error on '" << server_host << "' for session: " << error.message();
		config->transport.stats->error(Error::RESOLVE_ERROR);
		stop_();
		transport_parent->transport_error(Error::UNDEF, os.str());
	      }
	  }
      }

      void start_connect()
      {
	proto->get_endpoint(config->transport.remote_list);
	OPENVPN_LOG("Contacting " << proto->server_endpoint_addr() << " via " << proto->proto());
	transport_parent->transport_wait();
	proto->open();

	if (config->transport.socket_protect)
	  {
	    if (!config->transport.socket_protect->socket_protect(proto->native_handle(), server_endpoint_addr()))
	      {
		stop();
		std::ostringstream os;
		os << "socket_protect error (";
		os << proto->proto();
		os << ")";
		transport_parent->transport_error(Error::UNDEF, os.str());
		return;
	      }
	  }

	proto->async_connect([self=Ptr(this)](const openvpn_io::error_code &error) {
	    self->start_impl_udp(error);
	});
      }

      // start I/O on UDP socket
      virtual void start_impl_udp(const openvpn_io::error_code& error) = 0;

      virtual void stop_() = 0;

      openvpn_io::io_context& io_context;
      bool halt;

      TunProp::State::Ptr state;

      ClientConfig::Ptr config;
      TransportClientParent* transport_parent;
      TunClientParent* tun_parent;

      ProtoBase::Ptr proto;

      ActionList::Ptr remove_cmds;

      std::string server_host;
      std::string server_port;

      int peer_id;
    };

#ifdef ENABLE_KOVPN
    #include <openvpn/kovpn/kovpncli.hpp>
    inline DCO::Ptr new_controller()
    {
      return KovpnClientConfig::new_controller();
    }
    inline TransportClient::Ptr ClientConfig::new_transport_client_obj(openvpn_io::io_context& io_context,
								       TransportClientParent* parent)
    {
      return TransportClient::Ptr(new KovpnClient(io_context, this, parent));
    }
#elif ENABLE_OVPNDCO
    #include <openvpn/dco/ovpndcocli.hpp>
    inline DCO::Ptr new_controller()
    {
      return ClientConfig::new_controller();
    }
    inline TransportClient::Ptr ClientConfig::new_transport_client_obj(openvpn_io::io_context& io_context,
								       TransportClientParent* parent)
    {
      return TransportClient::Ptr(new OvpnDcoClient(io_context, this, parent));
    }
#else
#error either ENABLE_KOVPN or ENABLE_OVPNDCO must be defined
#endif

    inline TunClient::Ptr ClientConfig::new_tun_client_obj(openvpn_io::io_context& io_context,
							   TunClientParent& parent,
							   TransportClient* transcli)
    {
      Client* cli = static_cast<Client*>(transcli);
      cli->tun_parent = &parent;
      return TunClient::Ptr(cli);
    }
  }
}
