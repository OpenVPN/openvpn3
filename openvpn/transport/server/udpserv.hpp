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

// UDP transport object specialized for server.

#ifndef OPENVPN_TRANSPORT_SERVER_UDPSERV_H
#define OPENVPN_TRANSPORT_SERVER_UDPSERV_H

#include <sstream>

#include <boost/asio.hpp>

#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/common/port.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/addr/cidrmap.hpp>
#include <openvpn/transport/server/transbase.hpp>
#include <openvpn/transport/udplink.hpp>
#include <openvpn/transport/transmap.hpp>

namespace openvpn {
  namespace UDPTransport {

    class ServerConfig : public TransportServerFactory
    {
    public:
      typedef RCPtr<ServerConfig> Ptr;

      std::string local_ip;
      std::string local_port;
      Frame::Ptr frame;
      SessionStats::Ptr stats;
      int n_parallel;
      size_t transport_map_seed;

      TransportClientInstanceFactory::Ptr client_instance_factory;

      static Ptr new_obj()
      {
	return new ServerConfig;
      }

      virtual TransportServer::Ptr new_server_obj(boost::asio::io_service& io_service);

    private:
      ServerConfig()
	: n_parallel(8), transport_map_seed(0)
      {}
    };

    class Server : public TransportServer
    {
      friend class ServerConfig;  // calls constructor
      friend class Link<Server*>; // calls udp_read_handler and others

      typedef Link<Server*> LinkImpl;

      typedef TransportMap::Endpoint<IP::Addr> Endpoint;

      class Instance : public TransportClientInstanceSend
      {
	friend class Server;

      public:
	typedef RCPtr<Instance> Ptr;

	virtual bool defined() const
	{
	  return !halt;
	}

      private:
	Instance() : id(0), parent(nullptr), halt(false) {}

	virtual bool transport_send_const(const Buffer& buf)
	{
	  return parent->send(buf, &asio_endpoint);
	}

	virtual bool transport_send(BufferAllocated& buf)
	{
	  return parent->send(buf, &asio_endpoint);
	}

	virtual void stop()
	{
	  do_stop(true);
	}

	virtual const std::string& transport_info() const
	{
	  return info_;
	}

	void do_stop(const bool remove_self_from_map)
	{
	  if (!halt)
	    {
	      halt = true;
	      if (instance && instance->defined())
		instance->stop();
	      if (remove_self_from_map)
		parent->io_service.post(asio_dispatch_post_arg(&Server::remove_instance, parent, Ptr(this)));
	    }
	}

	// unique ID
	size_t id;

	// source address of client
	Endpoint endpoint;

	// equal to endpoint, but represented in Asio form
	AsioEndpoint asio_endpoint;

	// client information string
	std::string info_;

	// the client instance
	TransportClientInstanceRecv::Ptr instance;

	// our parent
	Server* parent;

	// indicates that objected is marked for delete
	bool halt;
      };

      typedef TransportMap::Map<Endpoint, Instance> InstanceMap;

    public:
      virtual std::string local_endpoint_info() const
      {
	std::ostringstream os;
	os << local_endpoint << "/UDP";
	return os.str();
      }

      virtual void start()
      {
	if (!impl)
	  {
	    halt = false;

	    // parse local endpoint
	    const IP::Addr ip_addr = IP::Addr::from_string(config->local_ip);
	    local_endpoint.address(ip_addr.to_asio());
	    local_endpoint.port(parse_port(config->local_port, "port"));

	    // open socket and bind to local address
	    socket.open(local_endpoint.protocol());
	    socket.bind(local_endpoint);

	    // start receiving data
	    impl.reset(new LinkImpl(this,
				    socket,
				    (*config->frame)[Frame::READ_LINK_UDP],
				    config->stats));
	    impl->start(config->n_parallel);
	  }
      }

      virtual void stop() { stop_(); }
      virtual ~Server() { stop_(); }

    private:
      Server(boost::asio::io_service& io_service_arg,
	     ServerConfig* config_arg)
	:  io_service(io_service_arg),
	   socket(io_service_arg),
	   config(config_arg),
	   halt(false),
	   clients(config_arg->transport_map_seed),
	   next_instance_id(1)
      {
      }

      void remove_instance(Instance::Ptr inst)
      {
	InstanceMap::const_iterator e = clients.find(inst->endpoint);
	if (e != clients.end() && inst->id == e->second->id)
	  {
	    OPENVPN_LOG("UDP Server: removing instance: " << e->second->info()); // fixme
	    clients.erase(e);
	  }
      }

      bool send(const Buffer& buf, const AsioEndpoint* ep)
      {
	if (impl)
	  return !impl->send(buf, ep);
	else
	  return false;
      }

      void udp_read_handler(PacketFrom::SPtr& pfp) // called by LinkImpl
      {
	if (halt)
	  return;

	OPENVPN_LOG("UDP incoming packet, size=" << pfp->buf.size()); // fixme

	Instance::Ptr blame;  // instance we will blame if exception is thrown
	Endpoint from;        // sender endpoint

	try {
	  from = Endpoint::from_asio(pfp->sender_endpoint);

	  // lookup endpoint in map, process packet if exists.
	  {
	    InstanceMap::iterator e = clients.find(from);
	    if (e != clients.end())
	      {
		OPENVPN_LOG("UDP existing client"); // fixme

		// found client instance matching endpoint
		TransportClientInstanceRecv* ci = e->second->instance.get();
		if (ci->defined())
		  {
		    blame = e->second;
		    ci->transport_recv(pfp->buf);
		    return;
		  }
		else
		  {
		    // found existing client, but it is halted
		    clients.erase(e);
		  }
	      }
	  }

	  // new client is connecting
	  {
	    TransportClientInstanceFactory* cif = config->client_instance_factory.get();
	    OPENVPN_LOG("UDP new client"); // fixme
	    if (cif->validate_initial_packet(pfp->buf))
	      {
		Instance::Ptr newinst = new Instance();
		newinst->id = next_instance_id++;
		newinst->endpoint = from;
		newinst->asio_endpoint = pfp->sender_endpoint;
		newinst->info_ = from.to_string();
		newinst->instance = cif->new_client_instance();
		newinst->parent = this;
		clients.add(from, newinst);
		blame = newinst;
		newinst->instance->start(newinst);
		newinst->instance->transport_recv(pfp->buf);
	      }
	  }
	}
	catch (const std::exception& e)
	  {
	    OPENVPN_LOG("Exception in udp_read_handler: " << e.what()); // fixme
	    if (blame)
	      blame->do_stop(true);

	    // fixme -- add additional error handling
	  }
      }

      void stop_()
      {
	if (!halt)
	  {
	    OPENVPN_LOG("Stopping clients..."); // fixme
	    halt = true;

	    // stop clients
	    {
	      for (InstanceMap::const_iterator i = clients.begin(); i != clients.end(); ++i)
		{
		  OPENVPN_LOG("Stopping client: " << i->second->info()); // fixme
		  i->second->do_stop(false);
		}
	      clients.clear();
	    }

	    // close UDP socket
	    if (impl)
	      impl->stop();
	    socket.close();
	  }
      }

      boost::asio::io_service& io_service;
      boost::asio::ip::udp::socket socket;
      ServerConfig::Ptr config;
      LinkImpl::Ptr impl;
      AsioEndpoint local_endpoint;
      bool halt;

      InstanceMap clients;
      size_t next_instance_id;
    };

    inline TransportServer::Ptr ServerConfig::new_server_obj(boost::asio::io_service& io_service)
    {
      return TransportServer::Ptr(new Server(io_service, this));
    }
  }
} // namespace openvpn

#endif
