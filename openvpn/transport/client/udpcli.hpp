//
//  udpcli.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TRANSPORT_CLIENT_UDPCLI_H
#define OPENVPN_TRANSPORT_CLIENT_UDPCLI_H

#include <sstream>

#include <boost/asio.hpp>

#include <openvpn/transport/udplink.hpp>
#include <openvpn/transport/endpoint_cache.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/transport/socket_protect.hpp>

namespace openvpn {
  namespace UDPTransport {

    class ClientConfig : public TransportClientFactory
    {
    public:
      typedef boost::intrusive_ptr<ClientConfig> Ptr;

      std::string server_host;
      std::string server_port;
      bool server_addr_float;
      int n_parallel;
      Frame::Ptr frame;
      SessionStats::Ptr stats;

      SocketProtect* socket_protect;

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TransportClient::Ptr new_client_obj(boost::asio::io_service& io_service,
						  TransportClientParent& parent);

      EndpointCache::Ptr endpoint_cache;

    private:
      ClientConfig()
	: server_addr_float(false),
	  n_parallel(8),
	  socket_protect(NULL)
      {}
    };

    class Client : public TransportClient
    {
      friend class ClientConfig;  // calls constructor
      friend class Link<Client*>; // calls udp_read_handler

      typedef Link<Client*> LinkImpl;

      typedef AsioDispatchResolve<Client,
				  void (Client::*)(const boost::system::error_code&, boost::asio::ip::udp::resolver::iterator),
				  boost::asio::ip::udp::resolver::iterator> AsioDispatchResolveUDP;

    public:
      virtual void start()
      {
	if (!impl)
	  {
	    halt = false;
	    if (config->endpoint_cache
		&& config->endpoint_cache->get_endpoint(config->server_host, config->server_port, server_endpoint))
	      {
		start_impl_();
	      }
	    else
	      {
		boost::asio::ip::udp::resolver::query query(config->server_host,
							    config->server_port);
		parent.transport_pre_resolve();
		resolver.async_resolve(query, AsioDispatchResolveUDP(&Client::do_resolve_, this));
	      }
	  }
      }

      virtual bool transport_send_const(const Buffer& buf)
      {
	return send(buf);
      }

      virtual bool transport_send(BufferAllocated& buf)
      {
	return send(buf);
      }

      virtual void server_endpoint_info(std::string& host, std::string& port, std::string& proto, std::string& ip_addr) const
      {
	host = config->server_host;
	port = config->server_port;
	const IP::Addr addr = server_endpoint_addr();
	proto = "UDP";
	proto += addr.version_string();
	ip_addr = addr.to_string();
      }

      virtual IP::Addr server_endpoint_addr() const
      {
	return IP::Addr::from_asio(server_endpoint.address());
      }

      virtual void stop() { stop_(); }
      virtual ~Client() { stop_(); }

    private:
      Client(boost::asio::io_service& io_service_arg,
	     ClientConfig* config_arg,
	     TransportClientParent& parent_arg)
	:  io_service(io_service_arg),
	   socket(io_service_arg),
	   config(config_arg),
	   parent(parent_arg),
	   resolver(io_service_arg),
	   halt(false)
      {
      }

      bool send(const Buffer& buf)
      {
	if (impl)
	  return impl->send(buf, NULL);
	else
	  return false;
      }

      void udp_read_handler(PacketFrom::SPtr& pfp) // called by LinkImpl
      {
	if (config->server_addr_float || pfp->sender_endpoint == server_endpoint)
	  parent.transport_recv(pfp->buf);
	else
	  config->stats->error(Error::BAD_SRC_ADDR);
      }

      void stop_()
      {
	if (!halt)
	  {
	    halt = true;
	    if (impl)
	      impl->stop();
	    socket.close();
	    resolver.cancel();
	  }
      }

      // called after DNS resolution has succeeded or failed
      void do_resolve_(const boost::system::error_code& error,
		       boost::asio::ip::udp::resolver::iterator endpoint_iterator)
      {
	if (!halt)
	  {
	    if (!error)
	      {
		// get resolved endpoint
		server_endpoint = *endpoint_iterator;
		start_impl_();
	      }
	    else
	      {
		std::ostringstream os;
		os << "DNS resolve error on '" << config->server_host << "' for UDP session: " << error.message();
		config->stats->error(Error::RESOLVE_ERROR);
		stop();
		parent.transport_error(Error::UNDEF, os.str());
	      }
	  }
      }

      void start_impl_()
      {
	if (config->endpoint_cache)
	  config->endpoint_cache->set_endpoint(config->server_host, server_endpoint);
	parent.transport_wait();
	socket.open(server_endpoint.protocol());
#ifdef OPENVPN_PLATFORM_TYPE_UNIX
	if (config->socket_protect)
	  {
	    if (!config->socket_protect->socket_protect(socket.native_handle()))
	      {
		config->stats->error(Error::SOCKET_PROTECT_ERROR);
		stop();
		parent.transport_error(Error::UNDEF, "socket_protect error (UDP)");
		return;
	      }
	  }
#endif
	socket.connect(server_endpoint);
	impl.reset(new LinkImpl(this,
				socket,
				(*config->frame)[Frame::READ_LINK_UDP],
				config->stats));
	impl->start(config->n_parallel);
	parent.transport_connecting();
      }

      boost::asio::io_service& io_service;
      boost::asio::ip::udp::socket socket;
      ClientConfig::Ptr config;
      TransportClientParent& parent;
      LinkImpl::Ptr impl;
      boost::asio::ip::udp::resolver resolver;
      UDPTransport::Endpoint server_endpoint;
      bool halt;
    };

    inline TransportClient::Ptr ClientConfig::new_client_obj(boost::asio::io_service& io_service,
							     TransportClientParent& parent)
    {
      return TransportClient::Ptr(new Client(io_service, this, parent));
    }
  }
} // namespace openvpn

#endif
