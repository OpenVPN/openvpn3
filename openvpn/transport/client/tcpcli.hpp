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

// TCP transport object specialized for client.

#ifndef OPENVPN_TRANSPORT_CLIENT_TCPCLI_H
#define OPENVPN_TRANSPORT_CLIENT_TCPCLI_H

#include <sstream>

#include <boost/asio.hpp>

#include <openvpn/transport/tcplink.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/transport/socket_protect.hpp>
#include <openvpn/client/remotelist.hpp>

namespace openvpn {
  namespace TCPTransport {

    class ClientConfig : public TransportClientFactory
    {
    public:
      typedef boost::intrusive_ptr<ClientConfig> Ptr;

      RemoteList::Ptr remote_list;
      size_t send_queue_max_size;
      size_t free_list_max_size;
      Frame::Ptr frame;
      SessionStats::Ptr stats;

      SocketProtect* socket_protect;

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TransportClient::Ptr new_client_obj(boost::asio::io_service& io_service,
						  TransportClientParent& parent);

    private:
      ClientConfig()
	: send_queue_max_size(1024),
	  free_list_max_size(8),
	  socket_protect(NULL)
      {}
    };

    class Client : public TransportClient
    {
      friend class ClientConfig;         // calls constructor
      friend class Link<Client*, false>; // calls tcp_read_handler

      typedef Link<Client*, false> LinkImpl;

      typedef AsioDispatchResolve<Client,
				  void (Client::*)(const boost::system::error_code&,
						   boost::asio::ip::tcp::resolver::iterator),
				  boost::asio::ip::tcp::resolver::iterator> AsioDispatchResolveTCP;

    public:
      virtual void start()
      {
	if (!impl)
	  {
	    halt = false;
	    if (config->remote_list->endpoint_available(&server_host, &server_port, NULL))
	      {
		start_connect_();
	      }
	    else
	      {
		boost::asio::ip::tcp::resolver::query query(server_host,
							    server_port);
		parent.transport_pre_resolve();
		resolver.async_resolve(query, AsioDispatchResolveTCP(&Client::do_resolve_, this));
	      }
	  }
      }

      virtual bool transport_send_const(const Buffer& buf)
      {
	return send_const(buf);
      }

      virtual bool transport_send(BufferAllocated& buf)
      {
	return send(buf);
      }

      virtual void server_endpoint_info(std::string& host, std::string& port, std::string& proto, std::string& ip_addr) const
      {
	host = server_host;
	port = server_port;
	const IP::Addr addr = server_endpoint_addr();
	proto = "TCP";
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

      bool send_const(const Buffer& cbuf)
      {
	if (impl)
	  {
	    BufferAllocated buf(cbuf, 0);
	    return impl->send(buf);
	  }
	else
	  return false;
      }

      bool send(BufferAllocated& buf)
      {
	if (impl)
	  return impl->send(buf);
	else
	  return false;
      }

      void tcp_eof_handler() // called by LinkImpl
      {
	config->stats->error(Error::NETWORK_EOF_ERROR);
	tcp_error_handler("NETWORK_EOF_ERROR");
      }

      void tcp_read_handler(BufferAllocated& buf) // called by LinkImpl
      {
	parent.transport_recv(buf);
      }

      void tcp_error_handler(const char *error) // called by LinkImpl
      {
	std::ostringstream os;
	os << "Transport error on '" << server_host << ": " << error;
	stop();
	parent.transport_error(Error::UNDEF, os.str());
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

      // do DNS resolve
      void do_resolve_(const boost::system::error_code& error,
		       boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
      {
	if (!halt)
	  {
	    if (!error)
	      {
		// save resolved endpoint list in remote_list
		config->remote_list->set_endpoint_list(endpoint_iterator);
		start_connect_();
	      }
	    else
	      {
		std::ostringstream os;
		os << "DNS resolve error on '" << server_host << "' for TCP session: " << error.message();
		config->stats->error(Error::RESOLVE_ERROR);
		stop();
		parent.transport_error(Error::UNDEF, os.str());
	      }
	  }
      }

      // do TCP connect
      void start_connect_()
      {
	config->remote_list->get_endpoint(server_endpoint);
	OPENVPN_LOG("Contacting " << server_endpoint << " via TCP");
	parent.transport_wait();
	parent.ip_hole_punch(server_endpoint_addr());
	socket.open(server_endpoint.protocol());
#ifdef OPENVPN_PLATFORM_TYPE_UNIX
	if (config->socket_protect)
	  {
	    if (!config->socket_protect->socket_protect(socket.native_handle()))
	      {
		config->stats->error(Error::SOCKET_PROTECT_ERROR);
		stop();
		parent.transport_error(Error::UNDEF, "socket_protect error (TCP)");
		return;
	      }
	  }
#endif
	socket.set_option(boost::asio::ip::tcp::no_delay(true));
	socket.async_connect(server_endpoint, asio_dispatch_connect(&Client::start_impl_, this));
      }

      // start I/O on TCP socket
      void start_impl_(const boost::system::error_code& error)
      {
	if (!halt)
	  {
	    if (!error)
	      {
		impl.reset(new LinkImpl(this,
					socket,
					config->send_queue_max_size,
					config->free_list_max_size,
					(*config->frame)[Frame::READ_LINK_TCP],
					config->stats));
		impl->start();
		parent.transport_connecting();
	      }
	    else
	      {
		std::ostringstream os;
		os << "TCP connect error on '" << server_host << ':' << server_port << "' (" << server_endpoint << "): " << error.message();
		config->stats->error(Error::TCP_CONNECT_ERROR);
		stop();
		parent.transport_error(Error::UNDEF, os.str());
	      }
	  }
      }

      std::string server_host;
      std::string server_port;

      boost::asio::io_service& io_service;
      boost::asio::ip::tcp::socket socket;
      ClientConfig::Ptr config;
      TransportClientParent& parent;
      LinkImpl::Ptr impl;
      boost::asio::ip::tcp::resolver resolver;
      TCPTransport::Endpoint server_endpoint;
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
