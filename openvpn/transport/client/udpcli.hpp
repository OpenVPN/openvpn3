#ifndef OPENVPN_TRANSPORT_CLIENT_UDPCLI_H
#define OPENVPN_TRANSPORT_CLIENT_UDPCLI_H

#include <sstream>

#include <boost/asio.hpp>

#include <openvpn/transport/udplink.hpp>
#include <openvpn/transport/client/transbase.hpp>

namespace openvpn {
  namespace UDPTransport {

    OPENVPN_EXCEPTION(udp_transport_resolve_error);

    class ClientConfig : public TransportClientFactory
    {
    public:
      typedef boost::intrusive_ptr<ClientConfig> Ptr;

      std::string server_host;
      std::string server_port;
      bool server_addr_float;
      int n_parallel;
      Frame::Ptr frame;
      ProtoStats::Ptr stats;

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TransportClient::Ptr new_client_obj(boost::asio::io_service& io_service,
						  TransportClientParent& parent);
    private:
      ClientConfig()
	: server_addr_float(false), n_parallel(8) {}
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
	    boost::asio::ip::udp::resolver::query query(config->server_host,
							config->server_port);
	    resolver.async_resolve(query, AsioDispatchResolveUDP(&Client::post_start_, this));
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

      virtual std::string server_endpoint_render() const
      {
	std::ostringstream os;
	os << "UDP " << server_endpoint;
	return os.str();
      }

      virtual boost::asio::ip::address server_endpoint_addr() const
      {
	return server_endpoint.address();
      }

      virtual void stop() { stop_(); }
      virtual ~Client() { stop_(); }

    private:
      Client(boost::asio::io_service& io_service_arg,
	     ClientConfig* config_arg,
	     TransportClientParent& parent_arg)
	:  io_service(io_service_arg),
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
	  config->stats->error(ProtoStats::BAD_SRC_ADDR);
      }

      void stop_()
      {
	if (impl)
	  {
	    impl->stop();
	    impl.reset();
	  }
	resolver.cancel();
	halt = true;
      }

      void post_start_(const boost::system::error_code& error,
		       boost::asio::ip::udp::resolver::iterator endpoint_iterator)
      {
	if (!halt)
	  {
	    if (!error)
	      {
		// get resolved endpoint
		server_endpoint = *endpoint_iterator;

		impl.reset(new LinkImpl(io_service,
					this,
					server_endpoint,
					REMOTE_CONNECT,
					false,
					config->frame,
					config->stats));
		impl->start(config->n_parallel);
		parent.transport_connected();
	      }
	    else
	      {
		std::ostringstream os;
		os << "DNS resolve error on '" << config->server_host << "' for UDP session: " << error;
		config->stats->error(ProtoStats::RESOLVE_ERROR);
		stop();
		udp_transport_resolve_error err(os.str());
		parent.transport_error(err);
	      }
	  }
      }

      boost::asio::io_service& io_service;
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
