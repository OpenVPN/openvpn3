//
//  httpcli.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TRANSPORT_CLIENT_HTTPCLI_H
#define OPENVPN_TRANSPORT_CLIENT_HTTPCLI_H

#include <string>
#include <sstream>

#include <boost/asio.hpp>

#include <openvpn/common/hexstr.hpp> // fixme
#include <openvpn/common/string.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/transport/tcplink.hpp>
#include <openvpn/transport/endpoint_cache.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/transport/socket_protect.hpp>
#include <openvpn/http/request.hpp> // fixme
#include <openvpn/http/reply.hpp>
#include <openvpn/proxy/proxyauth.hpp>

namespace openvpn {
  namespace HTTPProxyTransport {

    class Options : public RC<thread_safe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<Options> Ptr;

      std::string host;
      std::string port;
      std::string username;
      std::string password;

      // previously generated cookie being returned to us,
      // minus any prefix.
      //std::string cookie; // fixme

      // opaque string that we will prepend to any generated
      // cookies.
      //std::string cookie_prefix; // fixme
    };

    // We need access to RAND_API and CRYPTO_API implementations, because proxy
    // authentication methods tend to require crypto and random functionality.
    template <typename RAND_API, typename CRYPTO_API>
    class ClientConfig : public TransportClientFactory
    {
    public:
      typedef boost::intrusive_ptr<ClientConfig> Ptr;

      std::string server_host;
      std::string server_port;
      size_t send_queue_max_size;
      size_t free_list_max_size;
      Frame::Ptr frame;
      SessionStats::Ptr stats;

      Options::Ptr http_proxy_options;

      typename RAND_API::Ptr rng; // random data source

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
	: send_queue_max_size(1024),
	  free_list_max_size(8),
	  socket_protect(NULL)
      {}
    };

    template <typename RAND_API, typename CRYPTO_API>
    class Client : public TransportClient
    {
      friend class ClientConfig<RAND_API, CRYPTO_API>;  // calls constructor
      friend class TCPTransport::Link<Client*, false>;  // calls tcp_read_handler

      typedef TCPTransport::Link<Client*, false> LinkImpl;

      typedef AsioDispatchResolve<Client,
				  void (Client::*)(const boost::system::error_code&, boost::asio::ip::tcp::resolver::iterator),
				  boost::asio::ip::tcp::resolver::iterator> AsioDispatchResolveTCP;

      enum {
	Connected=200,
	ProxyAuthenticationRequired=407,
      };

    public:
      virtual void start()
      {
	if (!impl)
	  {
	    if (!config->http_proxy_options)
	      {
		parent.proxy_error("http_proxy_options not defined", false);
		return;
	      }

	    halt = false;
	    if (config->endpoint_cache
		&& config->endpoint_cache->get_endpoint(config->http_proxy_options->host,
							config->http_proxy_options->port,
							server_endpoint))
	      {
		start_connect_();
	      }
	    else
	      {
		boost::asio::ip::tcp::resolver::query query(config->http_proxy_options->host,
							    config->http_proxy_options->port);
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
	host = config->server_host;
	port = config->server_port;
	const IP::Addr addr = server_endpoint_addr();
	proto = "TCP";
	proto += addr.version_string();
	proto += "-via-HTTP";
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
	     ClientConfig<RAND_API, CRYPTO_API>* config_arg,
	     TransportClientParent& parent_arg)
	:  io_service(io_service_arg),
	   socket(io_service_arg),
	   config(config_arg),
	   parent(parent_arg),
	   resolver(io_service_arg),
	   halt(false),
	   n_transactions(0),
	   proxy_data_bytes(0),
	   proxy_established(false),
	   http_reply_status(HTTP::ReplyParser::pending)
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

      void tcp_error_handler(const char *error) // called by LinkImpl and internally
      {
	std::ostringstream os;
	os << "Transport error on '" << config->server_host << ": " << error << " (HTTP proxy)";
	stop();
	parent.transport_error(os.str());
      }

      void proxy_error(const char *what, const bool need_creds)
      {
	std::ostringstream os;
	os << "on " << config->http_proxy_options->host << ':' << config->http_proxy_options->port << ": " << what;
	stop();
	parent.proxy_error(os.str(), need_creds);
      }

      void tcp_read_handler(BufferAllocated& buf) // called by LinkImpl
      {
	if (proxy_established)
	  parent.transport_recv(buf);
	else
	  {
	    try {
	      proxy_read_handler(buf);
	    }
	    catch (const std::exception& e)
	      {
		proxy_error(e.what(), false);
	      }
	  }
      }

      void tcp_eof_handler() // called by LinkImpl
      {
	if (proxy_established)
	  {
	    config->stats->error(Error::NETWORK_EOF_ERROR);
	    tcp_error_handler("NETWORK_EOF_ERROR");
	  }
	else
	  {
	    try {
	      proxy_eof_handler();
	    }
	    catch (const std::exception& e)
	      {
		proxy_error(e.what(), false);
	      }
	  }
      }

      void proxy_read_handler(BufferAllocated& buf)
      {
	OPENVPN_LOG("FROM PROXY: " << buf.to_string()); // fixme

	if (http_reply_status == HTTP::ReplyParser::pending)
	  {
	    // for anti-DoS, only allow a maximum number of chars in HTTP response
	    proxy_data_bytes += buf.size();
	    if (proxy_data_bytes > 16384)
	      throw Exception("HTTP proxy header too large");
	    
	    for (size_t i = 0; i < buf.size(); ++i)
	      {
		http_reply_status = http_parser.consume(http_reply, (char)buf[i]);
		if (http_reply_status != HTTP::ReplyParser::pending)
		  {
		    buf.advance(i+1);
		    if (http_reply_status == HTTP::ReplyParser::success)
		      {
			OPENVPN_LOG("*** HTTP header parse complete, resid_size=" << buf.size()); // fixme
			OPENVPN_LOG(http_reply.to_string()); // fixme
			    
			// we are connected, switch socket to tunnel mode
			if (http_reply.status_code == Connected)
			  {
			    // switch socket from HTTP proxy handshake mode to OpenVPN protocol mode
			    proxy_established = true;
			    impl->set_raw_mode(false);
			    impl->inject(buf);
			    parent.transport_connecting();
			  }
		      }
		    else
		      {
			throw Exception("HTTP proxy header parse error");
		      }
		    break;
		  }
	      }
	  }
      }

      HTTPProxy::ProxyAuthenticate::Ptr get_proxy_authenticate_header(const char *type)
      {
	for (HTTP::HeaderList::const_iterator i = http_reply.headers.begin(); i != http_reply.headers.end(); ++i)
	  {
	    const HTTP::Header& h = *i;
	    if (string::strcasecmp(h.name, "proxy-authenticate") == 0)
	      {
		HTTPProxy::ProxyAuthenticate::Ptr pa = new HTTPProxy::ProxyAuthenticate(h.value);
		if (string::strcasecmp(type, pa->method) == 0)
		  return pa;
	      }
	  }
	return HTTPProxy::ProxyAuthenticate::Ptr();
      }

      void proxy_eof_handler()
      {
	if (http_reply_status == HTTP::ReplyParser::success
	    && http_reply.status_code == ProxyAuthenticationRequired)
	  {
	    if (n_transactions <= 1)
	      {
		OPENVPN_LOG("*** PROXY AUTHENTICATION REQUIRED"); // fixme

		if (config->http_proxy_options->username.empty())
		  {
		    proxy_error("HTTP proxy requires credentials", true);
		    return;
		  }

		HTTPProxy::ProxyAuthenticate::Ptr pa;

		// NTLM
		pa = get_proxy_authenticate_header("ntlm");
		if (pa)
		  {
		    ntlm_auth_phase_1(*pa);
		    return;
		  }

		// Digest
		pa = get_proxy_authenticate_header("digest");
		if (pa)
		  {
		    digest_auth(*pa);
		    return;
		  }

		// Digest
		pa = get_proxy_authenticate_header("basic");
		if (pa)
		  {
		    basic_auth(*pa);
		    return;
		  }
		throw Exception("HTTP proxy-authenticate method must be Basic, Digest, or NTLM");
	      }
	    else
	      {
		proxy_error("credentials were not accepted", true);
		return;
	      }
	  }
	else if (http_reply_status == HTTP::ReplyParser::pending)
	  throw Exception("HTTP proxy unexpected EOF: reply incomplete");
	else
	  throw Exception("HTTP proxy general error");
      }

      void ntlm_auth_phase_1(HTTPProxy::ProxyAuthenticate& pa)
      {
	OPENVPN_LOG("Proxy method: NTLM" << std::endl << pa.to_string()); // fixme
      }

      void digest_auth(HTTPProxy::ProxyAuthenticate& pa)
      {
	OPENVPN_LOG("Proxy method: Digest" << std::endl << pa.to_string()); // fixme
      }

      void basic_auth(HTTPProxy::ProxyAuthenticate& pa)
      {
	OPENVPN_LOG("Proxy method: Basic" << std::endl << pa.to_string()); // fixme

	std::ostringstream os;
	gen_user_agent(os);
	os << "Proxy-Authorization: Basic "
	   << base64->encode(config->http_proxy_options->username + ':' + config->http_proxy_options->password)
	   << "\r\n";
	http_request = os.str();
	reset();
	start_connect_();
      }

      void gen_user_agent(std::ostringstream& os)
      {
	os << "User-Agent: OpenVPN\r\n";
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
		// get resolved endpoint
		server_endpoint = *endpoint_iterator;
		start_connect_();
	      }
	    else
	      {
		std::ostringstream os;
		os << "DNS resolve error on '" << config->server_host << "' for TCP (HTTP proxy): " << error;
		config->stats->error(Error::RESOLVE_ERROR);
		stop();
		parent.transport_error(os.str());
	      }
	  }
      }

      void reset()
      {
	stop();
	halt = false;
	proxy_data_bytes = 0;
	proxy_established = false;
	http_reply_status = HTTP::ReplyParser::pending;
	http_reply.reset();
	http_parser.reset();
      }

      // do TCP connect
      void start_connect_()
      {
	socket.open(server_endpoint.protocol());
#ifdef OPENVPN_PLATFORM_TYPE_UNIX
	if (config->socket_protect)
	  {
	    if (!config->socket_protect->socket_protect(socket.native_handle()))
	      {
		config->stats->error(Error::SOCKET_PROTECT_ERROR);
		stop();
		parent.transport_error("socket_protect error (HTTP Proxy)");
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
		if (config->endpoint_cache)
		  config->endpoint_cache->set_endpoint(config->http_proxy_options->host, server_endpoint);
		impl.reset(new LinkImpl(this,
					socket,
					config->send_queue_max_size,
					config->free_list_max_size,
					(*config->frame)[Frame::READ_LINK_TCP],
					config->stats));
		impl->set_raw_mode(true);
		impl->start();
		++n_transactions;

		// tell proxy to connect through to OpenVPN server
		BufferAllocated buf;
		create_http_connect_msg(buf);
		send(buf);
	      }
	    else
	      {
		std::ostringstream os;
		os << "TCP connect error on '" << config->server_host << "' for TCP-via-HTTP-proxy session: " << error.message();
		config->stats->error(Error::TCP_CONNECT_ERROR);
		stop();
		parent.transport_error(os.str());
	      }
	  }
      }

      // create HTTP CONNECT message
      void create_http_connect_msg(BufferAllocated& buf)
      {
	std::ostringstream os;
	os << "CONNECT " << config->server_host << ':' << config->server_port << " HTTP/1.0\r\n"
	   << http_request<< "\r\n";
	const std::string str = os.str();
	http_request = "";

	OPENVPN_LOG("TO PROXY: " << str); // fixme

	config->frame->prepare(Frame::WRITE_HTTP_PROXY, buf);
	buf.write((const unsigned char *)str.c_str(), str.length());
      }

      boost::asio::io_service& io_service;
      boost::asio::ip::tcp::socket socket;
      typename ClientConfig<RAND_API, CRYPTO_API>::Ptr config;
      TransportClientParent& parent;
      typename LinkImpl::Ptr impl;
      boost::asio::ip::tcp::resolver resolver;
      TCPTransport::Endpoint server_endpoint;
      bool halt;

      unsigned int n_transactions;
      size_t proxy_data_bytes;
      bool proxy_established;
      HTTP::ReplyParser::status http_reply_status;
      HTTP::Reply http_reply;
      HTTP::ReplyParser http_parser;
      std::string http_request;
    };

    template <typename RAND_API, typename CRYPTO_API>
    inline TransportClient::Ptr ClientConfig<RAND_API, CRYPTO_API>::new_client_obj(boost::asio::io_service& io_service, TransportClientParent& parent)
    {
      return TransportClient::Ptr(new Client<RAND_API, CRYPTO_API>(io_service, this, parent));
    }
  }
} // namespace openvpn

#endif
