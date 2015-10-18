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

// General purpose HTTP/HTTPS/Web-services client.
// Supports:
//   * asynchronous I/O through Asio
//   * http/https
//   * chunking
//   * keepalive
//   * connect and overall timeouts
//   * GET, POST, etc.
//   * any OpenVPN SSL module (OpenSSL, PolarSSL)
//   * server CA bundle
//   * client certificate
//   * HTTP basic auth
//   * limits on content-size, header-size, and number of headers
//   * cURL not needed
//
//  See test/ws/wstest.cpp for usage examples including Dropwizard REST/JSON API client.
//  See test/ws/asprof.cpp for sample AS REST API client.

#ifndef OPENVPN_WS_HTTPCLI_H
#define OPENVPN_WS_HTTPCLI_H

#include <string>
#include <vector>
#include <sstream>
#include <algorithm>         // for std::min, std::max

#include <openvpn/common/platform.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/common/olong.hpp>
#include <openvpn/common/arraysize.hpp>
#include <openvpn/common/asiopolysock.hpp>
#include <openvpn/error/error.hpp>
#include <openvpn/buffer/bufstream.hpp>
#include <openvpn/http/reply.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/time/coarsetime.hpp>
#include <openvpn/transport/tcplink.hpp>
#include <openvpn/transport/client/transbase.hpp>
#include <openvpn/ws/httpcommon.hpp>
#include <openvpn/ws/httpcreds.hpp>

#if defined(OPENVPN_PLATFORM_WIN)
#include <openvpn/win/scoped_handle.hpp>
#include <openvpn/win/winerr.hpp>
#endif

namespace openvpn {
  namespace WS {
    namespace Client {

      OPENVPN_EXCEPTION(http_client_exception);

      struct Status
      {
	// Error codes
	enum {
	  E_SUCCESS=0,
	  E_RESOLVE,
	  E_CONNECT,
	  E_TRANSPORT,
	  E_PROXY,
	  E_TCP,
	  E_HTTP,
	  E_EXCEPTION,
	  E_HEADER_SIZE,
	  E_CONTENT_SIZE,
	  E_EOF_SSL,
	  E_EOF_TCP,
	  E_CONNECT_TIMEOUT,
	  E_GENERAL_TIMEOUT,

	  N_ERRORS
	};

	static std::string error_str(const size_t status)
	{
	  static const char *error_names[] = {
	    "E_SUCCESS",
	    "E_RESOLVE",
	    "E_CONNECT",
	    "E_TRANSPORT",
	    "E_PROXY",
	    "E_TCP",
	    "E_HTTP",
	    "E_EXCEPTION",
	    "E_HEADER_SIZE",
	    "E_CONTENT_SIZE",
	    "E_EOF_SSL",
	    "E_EOF_TCP",
	    "E_CONNECT_TIMEOUT",
	    "E_GENERAL_TIMEOUT",
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

	Config() : connect_timeout(0),
		   general_timeout(0),
		   max_headers(0),
		   max_header_bytes(0),
		   max_content_bytes(0),
		   msg_overhead_bytes(0) {}

	SSLFactoryAPI::Ptr ssl_factory;
	TransportClientFactory::Ptr transcli;
	std::string user_agent;
	unsigned int connect_timeout;
	unsigned int general_timeout;
	unsigned int max_headers;
	unsigned int max_header_bytes;
	olong max_content_bytes;
	unsigned int msg_overhead_bytes;
	Frame::Ptr frame;
	SessionStats::Ptr stats;
      };

      struct Host {
	std::string host;
	std::string hint;   // overrides host for transport, may be IP address
	std::string cn;     // host for CN verification, defaults to host if empty
	std::string head;   // host to send in HTTP header, defaults to host if empty
	std::string port;

	const std::string& host_transport() const
	{
	  return hint.empty() ? host : hint;
	}

	const std::string& host_cn() const
	{
	  return cn.empty() ? host : cn;
	}

	const std::string& host_head() const
	{
	  return head.empty() ? host : head;
	}

	std::string host_port_str() const
	{
	  return host + ':' + port;
	}
      };

      struct Request {
	void set_creds(const Creds& creds)
	{
	  username = creds.username;
	  password = creds.password;
	}

	std::string method;
	std::string uri;
	std::string username;
	std::string password;
      };

      struct ContentInfo {
	// content length if Transfer-Encoding: chunked
	static constexpr olong CHUNKED = -1;

	ContentInfo()
	  : length(0),
	    keepalive(false) {}

	std::string type;
	std::string content_encoding;
	olong length;
	bool keepalive;
	std::vector<std::string> extra_headers;
      };

      class HTTPCore;
      typedef HTTPBase<HTTPCore, Config, Status, HTTP::ReplyType, ContentInfo, olong, RC<thread_unsafe_refcount>> Base;

      class HTTPCore : public Base, public TransportClientParent
      {
      public:
	friend Base;

	typedef RCPtr<HTTPCore> Ptr;

	struct AsioProtocol
	{
	  typedef AsioPolySock::Base socket;
	};

	HTTPCore(asio::io_context& io_context_arg,
	     const Config::Ptr& config_arg)
	  : Base(config_arg),
	    io_context(io_context_arg),
	    alive(false),
	    resolver(io_context_arg),
	    connect_timer(io_context_arg),
	    general_timer(io_context_arg),
	    general_timeout_coarse(Time::Duration::binary_ms(512), Time::Duration::binary_ms(1024))
	{
	}

	virtual ~HTTPCore()
	{
	  stop();
	}

	bool is_alive() const
	{
	  return alive;
	}

	void start_request()
	{
	  if (!is_ready())
	    throw http_client_exception("not ready");
	  ready = false;
	  asio::post(io_context, [self=Ptr(this)]()
		     {
		       self->handle_request();
		     });
	}

	void stop()
	{
	  if (!halt)
	    {
	      halt = true;
	      ready = false;
	      alive = false;
	      if (transcli)
		transcli->stop();
	      if (link)
		link->stop();
	      if (socket)
		socket->close();
	      resolver.cancel();
	      general_timer.cancel();
	      connect_timer.cancel();
	    }
	}

	const HTTP::Reply& reply() const {
	  return request_reply();
	}

	std::string remote_endpoint_str() const
	{
	  try {
	    if (socket)
	      return socket->remote_endpoint_str();
	  }
	  catch (const std::exception& e)
	    {
	    }
	  return "[unknown endpoint]";
	}

	bool remote_ip_port(IP::Addr& addr, unsigned int& port) const
	{
	  if (socket)
	    return socket->remote_ip_port(addr, port);
	  else
	    return false;
	}

	// Return the current Host object, but
	// set the hint/port fields to the live
	// IP address/port of the connection.
	Host host_hint()
	{
	  Host h = host;
	  if (socket)
	    {
	      IP::Addr addr;
	      unsigned int port;
	      if (socket->remote_ip_port(addr, port))
		{
		  h.hint = addr.to_string();
		  h.port = std::to_string(port);
		}
	    }
	  return h;
	}

	// virtual methods

	virtual Host http_host() = 0;

	virtual Request http_request() = 0;

	virtual ContentInfo http_content_info()
	{
	  return ContentInfo();
	}

	virtual BufferPtr http_content_out()
	{
	  return BufferPtr();
	}

	virtual void http_content_out_needed()
	{
	}

	virtual void http_headers_received()
	{
	}

	virtual void http_headers_sent(const Buffer& buf)
	{
	}

	virtual void http_mutate_resolver_results(asio::ip::tcp::resolver::results_type& results)
	{
	}

	virtual void http_content_in(BufferAllocated& buf) = 0;

	virtual void http_done(const int status, const std::string& description) = 0;

	virtual void http_keepalive_close(const int status, const std::string& description)
	{
	}

      private:
	typedef TCPTransport::Link<AsioProtocol, HTTPCore*, false> LinkImpl;
	friend LinkImpl; // calls tcp_* handlers

	void verify_frame()
	{
	  if (!frame)
	    throw http_client_exception("frame undefined");
	}

	void activity(const bool init, const Time& now)
	{
	  if (general_timeout_duration.defined())
	    {
	      const Time next = now + general_timeout_duration;
	      if (init || !general_timeout_coarse.similar(next))
		{
		  general_timeout_coarse.reset(next);
		  general_timer.expires_at(next);
		  general_timer.async_wait([self=Ptr(this)](const asio::error_code& error)
					   {
					     if (!error)
					       self->general_timeout_handler(error);
					   });
		}
	    }
	  else if (init)
	    general_timer.cancel();
	}

	void activity(const bool init)
	{
	  activity(init, Time::now());
	}

	void handle_request() // called by Asio
	{
	  if (halt)
	    return;

	  try {
	    if (ready)
	      throw http_client_exception("handle_request called in ready state");

	    verify_frame();

	    const Time now = Time::now();
	    general_timeout_duration = Time::Duration::seconds(config->general_timeout);
	    activity(true, now);

	    if (alive)
	      {
		generate_request();
	      }
	    else
	      {
		host = http_host();
#ifdef ASIO_HAS_LOCAL_SOCKETS
		if (host.port == "unix") // unix domain socket
		  {
		    asio::local::stream_protocol::endpoint ep(host.host);
		    AsioPolySock::Unix* s = new AsioPolySock::Unix(io_context, 0);
		    socket.reset(s);
		    s->socket.async_connect(ep,
					    [self=Ptr(this)](const asio::error_code& error)
					    {
					      self->handle_unix_connect(error);
					    });
		  }
		else
#endif
#ifdef OPENVPN_PLATFORM_WIN
		  if (host.port == "np") // windows named pipe
		  {
		    const HANDLE h = ::CreateFile(
		        host.host.c_str(),
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_FLAG_OVERLAPPED,
			NULL);
		    if (!Win::Handle::defined(h))
		      {
			const Win::LastError err;
			OPENVPN_THROW(http_client_exception, "failed to open existing named pipe: " << host.host << " : " << err.message());
		      }
		    socket.reset(new AsioPolySock::NamedPipe(asio::windows::stream_handle(io_context, h), 0));
		    do_connect(true);
		  }
		else
#endif
		  {
		    if (host.port.empty())
		      host.port = config->ssl_factory ? "443" : "80";

		    if (config->ssl_factory)
		      ssl_sess = config->ssl_factory->ssl(host.host_cn());

		    if (config->transcli)
		      {
			transcli = config->transcli->new_transport_client_obj(io_context, *this);
			transcli->transport_start();
		      }
		    else
		      {
			resolver.async_resolve(host.host_transport(), host.port,
					       [self=Ptr(this)](const asio::error_code& error, asio::ip::tcp::resolver::results_type results)
					       {
						 self->handle_tcp_resolve(error, results);
					       });
		      }
		  }
		if (config->connect_timeout)
		  {
		    connect_timer.expires_at(now + Time::Duration::seconds(config->connect_timeout));
		    connect_timer.async_wait([self=Ptr(this)](const asio::error_code& error)
					     {
					       if (!error)
						 self->connect_timeout_handler(error);
					     });
		  }
	      }
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("handle_request", e);
	    }
	}

	void handle_tcp_resolve(const asio::error_code& error, // called by Asio
				asio::ip::tcp::resolver::results_type results)
	{
	  if (halt)
	    return;

	  if (error)
	    {
	      asio_error_handler(Status::E_RESOLVE, "handle_tcp_resolve", error);
	      return;
	    }

	  try {
	    // asio docs say this should never happen, but check just in case
	    if (results.empty())
	      OPENVPN_THROW_EXCEPTION("no results");

	    http_mutate_resolver_results(results);

	    AsioPolySock::TCP* s = new AsioPolySock::TCP(io_context, 0);
	    socket.reset(s);
	    async_connect(s->socket, results,
				[self=Ptr(this)](const asio::error_code& error, const asio::ip::tcp::endpoint& endpoint)
				{
				  self->handle_tcp_connect(error, endpoint);
				});
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("handle_tcp_resolve", e);
	    }
	}

	void handle_tcp_connect(const asio::error_code& error, // called by Asio
				const asio::ip::tcp::endpoint& endpoint)
	{
	  if (halt)
	    return;

	  if (error)
	    {
	      asio_error_handler(Status::E_CONNECT, "handle_tcp_connect", error);
	      return;
	    }

	  try {
	    do_connect(true);
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("handle_tcp_connect", e);
	    }
	}

#ifdef ASIO_HAS_LOCAL_SOCKETS
	void handle_unix_connect(const asio::error_code& error) // called by Asio
	{
	  if (halt)
	    return;

	  if (error)
	    {
	      asio_error_handler(Status::E_CONNECT, "handle_unix_connect", error);
	      return;
	    }

	  try {
	    do_connect(true);
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("handle_unix_connect", e);
	    }
	}
#endif

	void do_connect(const bool use_link)
	{
	  connect_timer.cancel();
	  set_default_stats();

	  if (use_link)
	    {
	      socket->set_cloexec();
	      link.reset(new LinkImpl(this,
				      *socket,
				      0, // send_queue_max_size (unlimited)
				      8, // free_list_max_size
				      (*frame)[Frame::READ_HTTP],
				      stats));
	      link->set_raw_mode(true);
	      link->start();
	    }

	  if (ssl_sess)
	    ssl_sess->start_handshake();

	  // xmit the request
	  generate_request();
	}

	void general_timeout_handler(const asio::error_code& e) // called by Asio
	{
	  if (!halt && !e)
	    error_handler(Status::E_GENERAL_TIMEOUT, "General timeout");
	}

	void connect_timeout_handler(const asio::error_code& e) // called by Asio
	{
	  if (!halt && !e)
	    error_handler(Status::E_CONNECT_TIMEOUT, "Connect timeout");
	}

	void set_default_stats()
	{
	  if (!stats)
	    stats.reset(new SessionStats());
	}

	void generate_request()
	{
	  rr_reset();
	  http_out_begin();

	  const Request req = http_request();
	  content_info = http_content_info();

	  outbuf.reset(new BufferAllocated(1024, BufferAllocated::GROW));
	  BufferStreamOut os(*outbuf);
	  os << req.method << ' ' << req.uri << " HTTP/1.1\r\n";
	  os << "Host: " << host.host_head() << "\r\n";
	  if (!config->user_agent.empty())
	    os << "User-Agent: " << config->user_agent << "\r\n";
	  if (!req.username.empty() || !req.password.empty())
	    os << "Authorization: Basic "
	       << base64->encode(req.username + ':' + req.password)
	       << "\r\n";
	  if (content_info.length)
	    os << "Content-Type: " << content_info.type << "\r\n";
	  if (content_info.length > 0)
	    os << "Content-Length: " << content_info.length << "\r\n";
	  else if (content_info.length == ContentInfo::CHUNKED)
	    os << "Transfer-Encoding: chunked" << "\r\n";
	  for (auto &h : content_info.extra_headers)
	    os << h << "\r\n";
	  if (!content_info.content_encoding.empty())
	    os << "Content-Encoding: " << content_info.content_encoding << "\r\n";
	  if (content_info.keepalive)
	    os << "Connection: keep-alive\r\n";
	  os << "Accept: */*\r\n";
	  os << "\r\n";

	  http_headers_sent(*outbuf);
	  http_out();
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
	  const bool in_transaction = !ready;
	  const bool keepalive = alive;
	  stop();
	  if (in_transaction)
	    http_done(errcode, err);
	  else if (keepalive)
	    http_keepalive_close(errcode, err); // keepalive connection close outside of transaction
	}

	// methods called by LinkImpl

	bool tcp_read_handler(BufferAllocated& b)
	{
	  if (halt)
	    return false;

	  try {
	    activity(false);
	    tcp_in(b); // call Base
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("tcp_read_handler", e);
	    }
	  return true;
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

	void base_http_content_out_needed()
	{
	  http_content_out_needed();
	}

	void base_http_out_eof()
	{
	}

	bool base_http_headers_received()
	{
	  http_headers_received();
	  return true; // continue to receive content
	}

	void base_http_content_in(BufferAllocated& buf)
	{
	  http_content_in(buf);
	}

	bool base_link_send(BufferAllocated& buf)
	{
	  activity(false);
	  if (transcli)
	    return transcli->transport_send(buf);
	  else
	    return link->send(buf);
	}

	bool base_send_queue_empty()
	{
	  if (transcli)
	    return transcli->transport_send_queue_empty();
	  else
	    return link->send_queue_empty();
	}

	void base_http_done_handler(BufferAllocated& residual,
				    const bool parent_handoff)
	{
	  if (halt)
	    return;
	  if (content_info.keepalive || parent_handoff)
	    {
	      general_timer.cancel();
	      alive = true;
	      ready = true;
	    }
	  else
	    stop();
	  http_done(Status::E_SUCCESS, "Succeeded");
	}

	void base_error_handler(const int errcode, const std::string& err)
	{
	  error_handler(errcode, err);
	}

	// TransportClientParent methods

	virtual bool transport_is_openvpn_protocol()
	{
	  return false;
	}

	virtual void transport_recv(BufferAllocated& buf)
	{
	  tcp_read_handler(buf);
	}

	virtual void transport_needs_send()
	{
	  tcp_write_queue_needs_send();
	}

	std::string err_fmt(const Error::Type fatal_err, const std::string& err_text)
	{
	  std::ostringstream os;
	  if (fatal_err != Error::SUCCESS)
	    os << Error::name(fatal_err) << " : ";
	  os << err_text;
	  return os.str();
	}

	virtual void transport_error(const Error::Type fatal_err, const std::string& err_text)
	{
	  return error_handler(Status::E_TRANSPORT, err_fmt(fatal_err, err_text));
	}

	virtual void proxy_error(const Error::Type fatal_err, const std::string& err_text)
	{
	  return error_handler(Status::E_PROXY, err_fmt(fatal_err, err_text));
	}

	virtual void ip_hole_punch(const IP::Addr& addr)
	{
	}

	virtual void transport_pre_resolve()
	{
	}

	virtual void transport_wait_proxy()
	{
	}

	virtual void transport_wait()
	{
	}

	virtual void disable_keepalive(unsigned int& keepalive_ping,
				       unsigned int& keepalive_timeout)
	{
	}

	virtual void transport_connecting()
	{
	  do_connect(false);
	}

	asio::io_context& io_context;

	bool alive;

	AsioPolySock::Base::Ptr socket;
	asio::ip::tcp::resolver resolver;

	Host host;

	LinkImpl::Ptr link;

	TransportClient::Ptr transcli;

	AsioTimer connect_timer;
	AsioTimer general_timer;

	Time::Duration general_timeout_duration;
	CoarseTime general_timeout_coarse;
      };

      template <typename PARENT>
      class HTTPDelegate : public HTTPCore
      {
      public:
	OPENVPN_EXCEPTION(http_delegate_error);

	typedef RCPtr<HTTPDelegate> Ptr;

	HTTPDelegate(asio::io_context& io_context,
		     const WS::Client::Config::Ptr& config,
		     PARENT* parent_arg)
	  : WS::Client::HTTPCore(io_context, config),
	    parent(parent_arg)
	{
	}

	void attach(PARENT* parent_arg)
	{
	  parent = parent_arg;
	}

	void detach(const bool keepalive=false)
	{
	  if (parent)
	    {
	      parent = nullptr;
	      if (!keepalive)
		stop();
	    }
	}

	virtual Host http_host()
	{
	  if (parent)
	    return parent->http_host(*this);
	  else
	    throw http_delegate_error("http_host");
	}

	virtual Request http_request()
	{
	  if (parent)
	    return parent->http_request(*this);
	  else
	    throw http_delegate_error("http_request");
	}

	virtual ContentInfo http_content_info()
	{
	  if (parent)
	    return parent->http_content_info(*this);
	  else
	    throw http_delegate_error("http_content_info");
	}

	virtual BufferPtr http_content_out()
	{
	  if (parent)
	    return parent->http_content_out(*this);
	  else
	    throw http_delegate_error("http_content_out");
	}

	virtual void http_content_out_needed()
	{
	  if (parent)
	    parent->http_content_out_needed(*this);
	  else
	    throw http_delegate_error("http_content_out_needed");
	}

	virtual void http_headers_received()
	{
	  if (parent)
	    parent->http_headers_received(*this);
	}

	virtual void http_headers_sent(const Buffer& buf)
	{
	  if (parent)
	    parent->http_headers_sent(*this, buf);
	}

	virtual void http_mutate_resolver_results(asio::ip::tcp::resolver::results_type& results)
	{
	  if (parent)
	    parent->http_mutate_resolver_results(*this, results);
	}

	virtual void http_content_in(BufferAllocated& buf)
	{
	  if (parent)
	    parent->http_content_in(*this, buf);
	}

	virtual void http_done(const int status, const std::string& description)
	{
	  if (parent)
	    parent->http_done(*this, status, description);
	}

	virtual void http_keepalive_close(const int status, const std::string& description)
	{
	  if (parent)
	    parent->http_keepalive_close(*this, status, description);
	}

      private:
	PARENT* parent;
      };
    }
  }
}

#endif
