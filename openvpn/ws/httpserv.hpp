//
//  OpenVPN
//
//  Copyright (C) 2012-2015 OpenVPN Technologies, Inc. All rights reserved.
//

#include <string>
#include <cstdint>
#include <unordered_map>
#include <utility> // for std::move
#include <memory>

#include <openvpn/common/options.hpp>
#include <openvpn/common/format.hpp>
#include <openvpn/buffer/bufstream.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/time/coarsetime.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/options/merge.hpp>
#include <openvpn/frame/frame_init.hpp>
#include <openvpn/linux/core.hpp>
#include <openvpn/http/request.hpp>
#include <openvpn/http/reply.hpp>
#include <openvpn/http/status.hpp>
#include <openvpn/transport/tcplink.hpp>
#include <openvpn/ws/httpcommon.hpp>
#include <openvpn/server/listenlist.hpp>

#ifndef OPENVPN_WS_HTTPSERV_H
#define OPENVPN_WS_HTTPSERV_H

namespace openvpn {
  namespace WS {
    namespace Server {

      OPENVPN_EXCEPTION(http_server_exception);

      typedef unsigned int client_t;
      typedef std::uint64_t content_len_t;

      struct Status
      {
	// Error codes
	enum {
	  E_SUCCESS=0,
	  E_TCP,
	  E_HTTP,
	  E_EXCEPTION,
	  E_HEADER_SIZE,
	  E_CONTENT_SIZE,
	  E_EOF_SSL,
	  E_EOF_TCP,
	  E_GENERAL_TIMEOUT,
	  E_EXTERNAL_STOP,

	  N_ERRORS
	};

	static std::string error_str(const size_t status)
	{
	  static const char *error_names[] = {
	    "E_SUCCESS",
	    "E_TCP",
	    "E_HTTP",
	    "E_EXCEPTION",
	    "E_HEADER_SIZE",
	    "E_CONTENT_SIZE",
	    "E_EOF_SSL",
	    "E_EOF_TCP",
	    "E_GENERAL_TIMEOUT",
	    "E_EXTERNAL_STOP",
	  };

	  static_assert(N_ERRORS == array_size(error_names), "HTTP error names array inconsistency");
	  if (status < N_ERRORS)
	    return error_names[status];
	  else
	    return "E_???";
	}
      };

      struct Config : public RC<thread_unsafe_refcount>
      {
	typedef boost::intrusive_ptr<Config> Ptr;

	Config()
	  : tcp_max(0),
	    general_timeout(15),
	    max_headers(0),
	    max_header_bytes(0),
	    max_content_bytes(0),
	    send_queue_max_size(0),
	    free_list_max_size(8)
	{
	}

	SSLFactoryAPI::Ptr ssl_factory;
	unsigned int tcp_max;
	unsigned int general_timeout;
	unsigned int max_headers;
	unsigned int max_header_bytes;
	content_len_t max_content_bytes;
	unsigned int send_queue_max_size;
	unsigned int free_list_max_size;
	std::string http_server_id;
	Frame::Ptr frame;
	SessionStats::Ptr stats;
      };

      struct ContentInfo {
	enum {
	  // content length if Transfer-Encoding: chunked
	  CHUNKED=-1
	};

	ContentInfo()
	  : http_status(0),
	    length(0),
	    keepalive(false)
	{
	}

	int http_status;
	std::string http_status_str; // optional
	std::string type;
	content_len_t length;
	bool keepalive;
      };

      class Listener : public RC<thread_unsafe_refcount>
      {
      public:
	class Client;

      private:
	typedef WS::HTTPBase<Client, Config, Status, HTTP::RequestType, ContentInfo, content_len_t> Base;

      public:
	class Client : public Base
	{
	  friend Base;
	  friend Listener;

	  typedef TCPTransport::Link<Client*, false> LinkImpl;
	  friend LinkImpl; // calls tcp_* handlers

	public:
	  typedef boost::intrusive_ptr<Client> Ptr;

	  class Initializer
	  {
	    friend Listener;
	    friend Client;

	    Initializer(boost::asio::io_service& io_service_arg,
			Listener* parent_arg,
			boost::asio::ip::tcp::socket* socket_arg,
			const client_t client_id_arg)
	      : io_service(io_service_arg),
		parent(parent_arg),
		socket(socket_arg),
		client_id(client_id_arg)
	    {
	    }

	    boost::asio::io_service& io_service;
	    Listener* parent;
	    std::unique_ptr<boost::asio::ip::tcp::socket> socket;
	    const client_t client_id;
	  };

	  struct Factory : public RC<thread_unsafe_refcount>
	  {
	    typedef boost::intrusive_ptr<Factory> Ptr;

	    virtual Client::Ptr new_client(Initializer& ci) = 0;
	  };

	  virtual ~Client()
	  {
	    stop(false);
	  }

	protected:
	  Client(Initializer& ci)
	    : Base(ci.parent->config),
	      io_service(ci.io_service),
	      sock(std::move(ci.socket)),
	      parent(ci.parent),
	      timeout_timer(ci.io_service),
	      client_id(ci.client_id),
	      keepalive(false)
	  {
	  }

	  void generate_reply_headers(const ContentInfo& ci)
	  {
	    http_out_begin();
	    outbuf.reset(new BufferAllocated(1024, BufferAllocated::GROW));
	    BufferStreamOut os(*outbuf);

	    os << "HTTP/1.1 " << ci.http_status << ' ';
	    if (ci.http_status_str.empty())
	      os << HTTP::Status::to_string(ci.http_status);
	    else
	      os << ci.http_status_str;
	    os << "\r\n";
	    if (!parent->config->http_server_id.empty())
	      os << "Server: " << parent->config->http_server_id << "\r\n";
	    os << "Date: " << date_time_rfc822() << "\r\n";
	    if (ci.length)
	      os << "Content-Type: " << ci.type << "\r\n";
	    if (ci.length > 0)
	      os << "Content-Length: " << ci.length << "\r\n";
	    else if (ci.length == ContentInfo::CHUNKED)
	      os << "Transfer-Encoding: chunked" << "\r\n";
	    if ((keepalive = ci.keepalive))
	      os << "Connection: keep-alive\r\n";
	    else
	      os << "Connection: close\r\n";
	    os << "\r\n";

	    http_headers_sent(*outbuf);
	    http_out();
	  }

	  void generate_custom_reply_headers(BufferPtr& buf)
	  {
	    http_out_begin();
	    outbuf = std::move(buf);
	    http_headers_sent(*outbuf);
	    http_out();
	  }

	  // return true if client asked for keepalive
	  bool keepalive_request()
	  {
	    return headers().get_value_trim("connection") == "keep-alive";
	  }

	  const HTTP::Request& request() const {
	    return request_reply();
	  }

	  void register_activity()
	  {
	    activity();
	  }

	  void external_stop(const std::string& description)
	  {
	    error_handler(Status::E_EXTERNAL_STOP, description);
	  }

	  std::string remote_endpoint_str()
	  {
	    try {
	      if (sock)
		return to_string(sock->remote_endpoint());
	    }
	    catch (const std::exception& e)
	      {
	      }
	    return "[unknown endpoint]";
	  }

	  boost::asio::io_service& io_service;
	  std::unique_ptr<boost::asio::ip::tcp::socket> sock;
	  Time::Duration timeout_duration;

	private:
	  void start()
	  {
	    timeout_coarse.init(Time::Duration::binary_ms(512), Time::Duration::binary_ms(1024));
	    link.reset(new LinkImpl(this,
				    *sock,
				    parent->config->send_queue_max_size,
				    parent->config->free_list_max_size,
				    (*parent->config->frame)[Frame::READ_HTTP],
				    stats));
	    link->set_raw_mode(true);
	    if (parent->config->ssl_factory)
	      ssl_sess = parent->config->ssl_factory->ssl();
	    restart();
	  }

	  void restart()
	  {
	    timeout_duration = Time::Duration::seconds(parent->config->general_timeout);
	    activity();
	    rr_reset();
	    ready = false;
	    link->start();
	  }

	  void stop(const bool remove_self_from_map)
	  {
	    if (halt)
	      return;
	    halt = true;
	    timeout_timer.cancel();
	    if (link)
	      link->stop();
	    sock.reset();
	    if (remove_self_from_map)
	      io_service.post(asio_dispatch_post_arg(&Listener::remove_client, parent, Ptr(this)));
	  }

	  client_t get_client_id() const
	  {
	    return client_id;
	  }

	  void activity()
	  {
	    if (timeout_duration.defined())
	      {
		const Time now = Time::now();
		const Time next = now + timeout_duration;
		if (!timeout_coarse.similar(next))
		  {
		    timeout_coarse.reset(next);
		    timeout_timer.expires_at(next);
		    timeout_timer.async_wait(asio_dispatch_timer(&Client::timeout_callback, this));
		  }
	      }
	  }

	  void timeout_callback(const boost::system::error_code& e)
	  {
	    if (halt || e)
	      return;
	    error_handler(Status::E_GENERAL_TIMEOUT, "General timeout");
	  }

	  // methods called by LinkImpl

	  bool tcp_read_handler(BufferAllocated& b)
	  {
	    if (halt)
	      return false;

	    try {
	      activity();
	      tcp_in(b); // call Base
	    }
	    catch (const std::exception& e)
	      {
		handle_exception("tcp_read_handler", e);
	      }

	    // don't requeue read if ready flag is set
	    return !ready;
	  }

	  void tcp_write_queue_needs_send()
	  {
	    if (halt)
	      return;

	    try {
	      http_out();
	    }
	    catch (const std::exception& e)
	      {
		handle_exception("tcp_write_queue_needs_send", e);
	      }
	  }

	  void tcp_eof_handler()
	  {
	    if (halt)
	      return;

	    try {
	      error_handler(Status::E_EOF_TCP, "TCP EOF");
	      return;
	    }
	    catch (const std::exception& e)
	      {
		handle_exception("tcp_eof_handler", e);
	      }
	  }

	  void tcp_error_handler(const char *error)
	  {
	    if (halt)
	      return;
	    error_handler(Status::E_TCP, std::string("HTTPCore TCP: ") + error);
	  }

	  // methods called by Base

	  BufferPtr base_http_content_out()
	  {
	    return http_content_out();
	  }

	  void base_http_out_eof()
	  {
	    if (http_out_eof())
	      {
		if (keepalive)
		  restart();
		else
		  error_handler(Status::E_SUCCESS, "Succeeded");
	      }
	  }

	  bool base_http_headers_received()
	  {
	    return http_headers_received();
	  }

	  void base_http_content_in(BufferAllocated& buf)
	  {
	    http_content_in(buf);
	  }

	  bool base_link_send(BufferAllocated& buf)
	  {
	    activity();
	    return link->send(buf);
	  }

	  bool base_send_queue_empty()
	  {
	    return link->send_queue_empty();
	  }

	  void base_http_done_handler(BufferAllocated& residual)
	  {
	    if (halt)
	      return;
	    ready = true; // stop accepting input
	    http_request_received(residual);
	  }

	  void base_error_handler(const int errcode, const std::string& err)
	  {
	    error_handler(errcode, err);
	  }

	  // error handlers

	  void asio_error_handler(int errcode, const char *func_name, const boost::system::error_code& error)
	  {
	    error_handler(errcode, std::string("HTTPCore Asio ") + func_name + ": " + error.message());
	  }

	  void handle_exception(const char *func_name, const std::exception& e)
	  {
	    error_handler(Status::E_EXCEPTION, std::string("HTTPCore Exception ") + func_name + ": " + e.what());
	  }

	  void error_handler(const int errcode, const std::string& err)
	  {
	    stop(true);
	    http_stop(errcode, err);
	  }

	  // virtual methods

	  virtual BufferPtr http_content_out()
	  {
	    return BufferPtr();
	  }

	  virtual bool http_headers_received()
	  {
	    return true;
	  }

	  virtual void http_request_received(BufferAllocated& residual)
	  {
	  }

	  virtual void http_content_in(BufferAllocated& buf)
	  {
	  }

	  virtual void http_headers_sent(const Buffer& buf)
	  {
	  }

	  virtual bool http_out_eof()
	  {
	    return true;
	  }

	  virtual void http_stop(const int status, const std::string& description)
	  {
	  }

	  Listener* parent;
	  AsioTimer timeout_timer;
	  CoarseTime timeout_coarse;
	  client_t client_id;
	  LinkImpl::Ptr link;
	  bool keepalive;
	};

      public:
	typedef boost::intrusive_ptr<Listener> Ptr;

	Listener(boost::asio::io_service& io_service_arg,
		 const Config::Ptr& config_arg,
		 const Listen::Item& listen_item_arg,
		 const Client::Factory::Ptr& client_factory_arg)
	  : io_service(io_service_arg),
	    listen_item(listen_item_arg),
	    config(config_arg),
	    client_factory(client_factory_arg),
	    halt(false),
	    acceptor(io_service_arg),
	    next_id(0)
	{
	}

	void start()
	{
	  if (halt)
	    return;

	  OPENVPN_LOG("HTTP" << (config->ssl_factory ? "S" : "") << " Listen: " << listen_item.to_string());

	  // parse address/port of local endpoint
	  if (!listen_item.proto.is_tcp())
	    throw option_error("only TCP supported");
	  const IP::Addr ip_addr = IP::Addr::from_string(listen_item.addr);
	  local_endpoint.address(ip_addr.to_asio());
	  local_endpoint.port(parse_port(listen_item.port, "port"));

	  // open socket and bind to local address
	  acceptor.open(local_endpoint.protocol());

	  // set socket flags
	  {
	    const int fd = acceptor.native_handle();
	    SockOpt::reuseport(fd);
	    SockOpt::reuseaddr(fd);
	  }

	  // bind to local address
	  acceptor.bind(local_endpoint);

	  // listen for incoming client connections
	  acceptor.listen();

	  // wait for incoming connection
	  queue_accept();
	}

	void stop()
	{
	  if (halt)
	    return;
	  halt = true;

	  acceptor.close();

	  // stop clients
	  for (ClientMap::const_iterator i = clients.begin(); i != clients.end(); ++i)
	    {
	      Client& c = *i->second;
	      c.stop(false);
	    }
	  clients.clear();
	}

      private:
	typedef std::unordered_map<client_t, Client::Ptr> ClientMap;

	void queue_accept()
	{
	  boost::asio::ip::tcp::socket* socket = new boost::asio::ip::tcp::socket(io_service);
	  acceptor.async_accept(*socket, asio_dispatch_accept_arg(&Listener::handle_accept, this, socket));
	}

	void handle_accept(boost::asio::ip::tcp::socket* socket,
			   const boost::system::error_code& error)
	{
	  std::unique_ptr<boost::asio::ip::tcp::socket> sock(socket);
	  if (halt)
	      return;

	  try {
	    if (!error)
	      {
		if (config->tcp_max && clients.size() >= config->tcp_max)
		  throw http_server_exception("max TCP clients exceeded");

		sock->non_blocking(true);

		const client_t client_id = next_id++;
		Client::Initializer ci(io_service, this, sock.release(), client_id);
		Client::Ptr cli = client_factory->new_client(ci);
		clients[client_id] = cli;
		cli->start();
	      }
	    else
	      throw http_server_exception("accept failed: " + error.message());
	  }
	  catch (const std::exception& e)
	    {
	      OPENVPN_LOG("exception in handle_accept: " << e.what());
	    }

	  queue_accept();
	}

	client_t new_client_id()
	{
	  while (true)
	    {
	      // find an ID that's not already in use
	      const client_t id = next_id++;
	      if (clients.find(id) == clients.end())
		return id;
	    }
	}

	void remove_client(Client::Ptr cli)
	{
	  remove_client_id(cli->get_client_id());
	}

	void remove_client_id(const client_t client_id)
	{
	  ClientMap::const_iterator e = clients.find(client_id);
	  if (e != clients.end())
	    clients.erase(e);
	}

	boost::asio::io_service& io_service;
	Listen::Item listen_item;
	Config::Ptr config;
	Client::Factory::Ptr client_factory;
	bool halt;

	boost::asio::ip::tcp::endpoint local_endpoint;
	boost::asio::ip::tcp::acceptor acceptor;

	client_t next_id;
	ClientMap clients;
      };

    }
  }
}

#endif
