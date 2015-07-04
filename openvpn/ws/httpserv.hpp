//
//  OpenVPN
//
//  Copyright (C) 2012-2015 OpenVPN Technologies, Inc. All rights reserved.
//

#include <unistd.h>    // for unlink()
#include <sys/stat.h>  // for chmod()

#include <string>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include <deque>
#include <utility> // for std::move
#include <memory>

#include <asio.hpp>

#include <openvpn/common/options.hpp>
#include <openvpn/common/format.hpp>
#include <openvpn/common/arraysize.hpp>
#include <openvpn/common/function.hpp>
#include <openvpn/common/sockopt.hpp>
#include <openvpn/common/asiopolysock.hpp>
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

#ifndef OPENVPN_HTTP_SERV_RC
#define OPENVPN_HTTP_SERV_RC RC<thread_unsafe_refcount>
#endif

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
	  E_PIPELINE_OVERFLOW,

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
	    "E_PIPELINE_OVERFLOW",
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
	typedef RCPtr<Config> Ptr;

	Config()
	  : unix_mode(0),
	    tcp_max(0),
	    general_timeout(15),
	    max_headers(0),
	    max_header_bytes(0),
	    max_content_bytes(0),
	    send_queue_max_size(0),
	    free_list_max_size(8),
	    pipeline_max_size(64)
	{
	}

	SSLFactoryAPI::Ptr ssl_factory;
	mode_t unix_mode;
	unsigned int tcp_max;
	unsigned int general_timeout;
	unsigned int max_headers;
	unsigned int max_header_bytes;
	content_len_t max_content_bytes;
	unsigned int send_queue_max_size;
	unsigned int free_list_max_size;
	unsigned int pipeline_max_size;
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
	std::string basic_realm;
	content_len_t length;
	bool keepalive;
      };

      class Listener : public RC<thread_unsafe_refcount>
      {
      public:
	class Client;

      private:
	typedef WS::HTTPBase<Client, Config, Status, HTTP::RequestType, ContentInfo, content_len_t, OPENVPN_HTTP_SERV_RC> Base;

      public:
	class Client : public Base
	{
	  friend Base;
	  friend Listener;

	public:
	  struct AsioProtocol
	  {
	    typedef AsioPolySock::Base socket;
	  };

	  typedef RCPtr<Client> Ptr;

	  class Initializer
	  {
	    friend Listener;
	    friend Client;

	    Initializer(asio::io_context& io_context_arg,
			Listener* parent_arg,
			AsioPolySock::Base::Ptr&& socket_arg,
			const client_t client_id_arg)
	      : io_context(io_context_arg),
		parent(parent_arg),
		socket(std::move(socket_arg)),
		client_id(client_id_arg)
	    {
	    }

	    asio::io_context& io_context;
	    Listener* parent;
	    AsioPolySock::Base::Ptr socket;
	    const client_t client_id;
	  };

	  struct Factory : public RC<thread_unsafe_refcount>
	  {
	    typedef RCPtr<Factory> Ptr;

	    virtual Client::Ptr new_client(Initializer& ci) = 0;
	  };

	  virtual ~Client()
	  {
	    stop(false);
	  }

	protected:
	  Client(Initializer& ci)
	    : Base(ci.parent->config),
	      io_context(ci.io_context),
	      sock(std::move(ci.socket)),
	      parent(ci.parent),
	      timeout_timer(ci.io_context),
	      client_id(ci.client_id),
	      keepalive(false),
	      handoff(false)
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
	    if (!ci.basic_realm.empty())
	      os << "WWW-Authenticate: Basic realm=\"" << ci.basic_realm << "\"\r\n";
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

	  std::string remote_endpoint_str() const
	  {
	    try {
	      if (sock)
		return sock->remote_endpoint_str();
	    }
	    catch (const std::exception& e)
	      {
	      }
	    return "[unknown endpoint]";
	  }

	  asio::io_context& io_context;
	  AsioPolySock::Base::Ptr sock;
	  std::deque<BufferAllocated> pipeline;
	  Time::Duration timeout_duration;

	private:
	  typedef TCPTransport::Link<AsioProtocol, Client*, false> LinkImpl;
	  friend LinkImpl; // calls tcp_* handlers

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
	    restart(true);
	  }

	  void restart(const bool initial)
	  {
	    timeout_duration = Time::Duration::seconds(parent->config->general_timeout);
	    activity();
	    rr_reset();
	    ready = false;
	    consume_pipeline();
	    if (initial || handoff)
	      link->start();
	    handoff = false;
	  }

	  void stop(const bool remove_self_from_map)
	  {
	    if (halt)
	      return;
	    halt = true;
	    http_destroy();
	    timeout_timer.cancel();
	    if (link)
	      link->stop();
	    sock.reset();
	    if (remove_self_from_map)
	      asio::post(io_context, [self=Ptr(this), parent=Listener::Ptr(parent)]()
			 {
			   parent->remove_client(self);
			 });
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
		    timeout_timer.async_wait([self=Ptr(this)](const asio::error_code& error)
                                             {
                                               self->timeout_callback(error);
                                             });
		  }
	      }
	  }

	  void timeout_callback(const asio::error_code& e)
	  {
	    if (halt || e)
	      return;
	    error_handler(Status::E_GENERAL_TIMEOUT, "General timeout");
	  }

	  void add_to_pipeline(BufferAllocated& buf)
	  {
	    if (buf.empty())
	      return;
	    if (pipeline.size() >= parent->config->pipeline_max_size)
	      error_handler(Status::E_PIPELINE_OVERFLOW, "Pipeline overflow");
	    pipeline.push_back(std::move(buf));
	  }

	  void consume_pipeline()
	  {
	    while (!pipeline.empty() && !ready)
	      {
		BufferAllocated buf(std::move(pipeline.front()));
		pipeline.pop_front();
		tcp_in(buf);
	      }
	  }

	  // methods called by LinkImpl

	  bool tcp_read_handler(BufferAllocated& b)
	  {
	    if (halt)
	      return false;

	    try {
	      activity();
	      if (ready)
		add_to_pipeline(b);
	      else
		tcp_in(b); // call Base
	    }
	    catch (const std::exception& e)
	      {
		handle_exception("tcp_read_handler", e);
	      }
	    return !handoff; // don't requeue read if handoff, i.e. parent wants to take control of session socket
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
		  restart(false);
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

	  void base_http_done_handler(BufferAllocated& residual,
				      const bool parent_handoff)
	  {
	    if (halt)
	      return;
	    ready = true;
	    handoff = parent_handoff;
	    add_to_pipeline(residual);
	    http_request_received();
	  }

	  void base_error_handler(const int errcode, const std::string& err)
	  {
	    error_handler(errcode, err);
	  }

	  // error handlers

	  void asio_error_handler(int errcode, const char *func_name, const asio::error_code& error)
	  {
	    error_handler(errcode, std::string("HTTPCore Asio ") + func_name + ": " + error.message());
	  }

	  void handle_exception(const char *func_name, const std::exception& e)
	  {
	    error_handler(Status::E_EXCEPTION, std::string("HTTPCore Exception ") + func_name + ": " + e.what());
	  }

	  void error_handler(const int errcode, const std::string& err)
	  {
	    http_stop(errcode, err);
	    stop(true);
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

	  virtual void http_request_received()
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

	  virtual void http_destroy()
	  {
	  }

	  Listener* parent;
	  AsioTimer timeout_timer;
	  CoarseTime timeout_coarse;
	  client_t client_id;
	  LinkImpl::Ptr link;
	  bool keepalive;
	  bool handoff;
	};

      public:
	typedef RCPtr<Listener> Ptr;

	Listener(asio::io_context& io_context_arg,
		 const Config::Ptr& config_arg,
		 const Listen::Item& listen_item_arg,
		 const Client::Factory::Ptr& client_factory_arg)
	  : io_context(io_context_arg),
	    listen_list(listen_item_arg),
	    config(config_arg),
	    client_factory(client_factory_arg),
	    halt(false),
	    next_id(0)
	{
	}

	Listener(asio::io_context& io_context_arg,
		 const Config::Ptr& config_arg,
		 const Listen::List& listen_list_arg,
		 const Client::Factory::Ptr& client_factory_arg)
	  : io_context(io_context_arg),
	    listen_list(listen_list_arg),
	    config(config_arg),
	    client_factory(client_factory_arg),
	    halt(false),
	    next_id(0)
	{
	}

	void start()
	{
	  if (halt)
	    return;

	  acceptors.reserve(listen_list.size());
	  for (const auto &listen_item : listen_list)
	    {
	      OPENVPN_LOG("HTTP" << (config->ssl_factory ? "S" : "") << " Listen: " << listen_item.to_string());

	      switch (listen_item.proto())
		{
		case Protocol::TCPv4:
		case Protocol::TCPv6:
		  {
		    AcceptorTCP::Ptr a(new AcceptorTCP(io_context));

		    // parse address/port of local endpoint
		    const IP::Addr ip_addr = IP::Addr::from_string(listen_item.addr);
		    a->local_endpoint.address(ip_addr.to_asio());
		    a->local_endpoint.port(HostPort::parse_port(listen_item.port, "http listen"));

		    // open socket
		    a->acceptor.open(a->local_endpoint.protocol());

		    // set socket flags
		    {
		      const int fd = a->acceptor.native_handle();
		      SockOpt::reuseport(fd);
		      SockOpt::reuseaddr(fd);
		    }

		    // bind to local address
		    a->acceptor.bind(a->local_endpoint);

		    // listen for incoming client connections
		    a->acceptor.listen();

		    // save acceptor
		    acceptors.push_back(a);

		    // queue accept on listen socket
		    queue_accept(acceptors.size() - 1);
		  }
		  break;
		case Protocol::UnixStream:
		  {
		    AcceptorUnix::Ptr a(new AcceptorUnix(io_context));

		    // set endpoint
		    ::unlink(listen_item.addr.c_str());
		    a->local_endpoint.path(listen_item.addr);

		    // open socket
		    a->acceptor.open(a->local_endpoint.protocol());

		    // bind to local address
		    a->acceptor.bind(a->local_endpoint);

		    // set socket permissions in filesystem
		    if (config->unix_mode)
		      {
			if (::chmod(listen_item.addr.c_str(), config->unix_mode) < 0)
			  throw http_server_exception("chmod failed on unix socket");
		      }

		    // listen for incoming client connections
		    a->acceptor.listen();

		    // save acceptor
		    acceptors.push_back(a);

		    // queue accept on listen socket
		    queue_accept(acceptors.size() - 1);
		  }
		  break;
		default:
		  throw http_server_exception("listen on unknown protocol");
		}
	    }
	}

	void stop()
	{
	  if (halt)
	    return;
	  halt = true;

	  // close acceptors
	  acceptors.close();

	  // stop clients
	  for (auto &c : clients)
	    c.second->stop(false);
	  clients.clear();
	}

      private:
	typedef std::unordered_map<client_t, Client::Ptr> ClientMap;

	struct AcceptorBase : public RC<thread_unsafe_refcount>
	{
	  typedef RCPtr<AcceptorBase> Ptr;

	  virtual void async_accept(Listener* listener,
				    const size_t acceptor_index,
				    asio::io_context& io_context) = 0;
	  virtual void close() = 0;
	};

	struct AcceptorSet : public std::vector<AcceptorBase::Ptr>
	{
	  void close()
	  {
	    for (auto &i : *this)
	      i->close();
	  }
	};

	struct AcceptorTCP : public AcceptorBase
	{
	  typedef RCPtr<AcceptorTCP> Ptr;

	  AcceptorTCP(asio::io_context& io_context)
	    : acceptor(io_context)
	  {
	  }

	  virtual void async_accept(Listener* listener,
				    const size_t acceptor_index,
				    asio::io_context& io_context) override
	  {
	    AsioPolySock::TCP::Ptr sock(new AsioPolySock::TCP(io_context, acceptor_index));
	    acceptor.async_accept(sock->socket, [listener=Listener::Ptr(listener), sock](const asio::error_code& error)
                                                {
                                                  listener->handle_accept(sock, error);
                                                });
	  }

	  virtual void close() override
	  {
	    acceptor.close();
	  }

	  asio::ip::tcp::endpoint local_endpoint;
	  asio::ip::tcp::acceptor acceptor;
	};

	struct AcceptorUnix : public AcceptorBase
	{
	  typedef RCPtr<AcceptorUnix> Ptr;

	  AcceptorUnix(asio::io_context& io_context)
	    : acceptor(io_context)
	  {
	  }

	  virtual void async_accept(Listener* listener,
				    const size_t acceptor_index,
				    asio::io_context& io_context) override
	  {
	    AsioPolySock::Unix::Ptr sock(new AsioPolySock::Unix(io_context, acceptor_index));
	    acceptor.async_accept(sock->socket, [listener=Listener::Ptr(listener), sock](const asio::error_code& error)
                                                {
                                                  listener->handle_accept(sock, error);
                                                });
	  }

	  virtual void close() override
	  {
	    acceptor.close();
	  }

	  asio::local::stream_protocol::endpoint local_endpoint;
	  asio::basic_socket_acceptor<asio::local::stream_protocol> acceptor;
	};

	void queue_accept(const size_t acceptor_index)
	{
	  acceptors[acceptor_index]->async_accept(this, acceptor_index, io_context);
	}

	void handle_accept(AsioPolySock::Base::Ptr sock, const asio::error_code& error)
	{
	  if (halt)
	      return;

	  const size_t acceptor_index = sock->index();

	  try {
	    if (!error)
	      {
		sock->non_blocking(true);

		if (config->tcp_max && clients.size() >= config->tcp_max)
		  throw http_server_exception("max TCP clients exceeded");
		if (!allow_client(*sock))
		  throw http_server_exception("client socket rejected");

		const client_t client_id = next_id++;
		Client::Initializer ci(io_context, this, std::move(sock), client_id);
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

	  queue_accept(acceptor_index);
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

	virtual bool allow_client(AsioPolySock::Base& sock)
	{
	  return true;
	}

	asio::io_context& io_context;
	Listen::List listen_list;
	Config::Ptr config;
	Client::Factory::Ptr client_factory;
	bool halt;

	AcceptorSet acceptors;

	client_t next_id;
	ClientMap clients;
      };

    }
  }
}

#endif
