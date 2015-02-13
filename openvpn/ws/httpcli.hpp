//
//  OpenVPN
//
//  Copyright (C) 2012-2015 OpenVPN Technologies, Inc. All rights reserved.
//

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

#include <algorithm>         // for std::min, std::max

#include <openvpn/common/base64.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/olong.hpp>
#include <openvpn/buffer/bufstream.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/transport/tcplink.hpp>
#include <openvpn/http/reply.hpp>
#include <openvpn/http/status.hpp>

namespace openvpn {
  namespace WS {
    namespace Client {

      // Error codes
      enum {
	E_SUCCESS=0,
	E_RESOLVE,
	E_CONNECT,
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

      OPENVPN_EXCEPTION(http_client_exception);

      inline std::string error_str(const size_t status)
      {
	static const char *error_names[] = {
	  "E_SUCCESS",
	  "E_RESOLVE",
	  "E_CONNECT",
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

      struct Config : public RC<thread_unsafe_refcount>
      {
	typedef boost::intrusive_ptr<Config> Ptr;

	Config() : connect_timeout(0),
		   general_timeout(0),
		   max_headers(0),
		   max_header_bytes(0),
		   max_content_bytes(0) {}

	SSLFactoryAPI::Ptr ssl_factory;
	std::string user_agent;
	unsigned int connect_timeout;
	unsigned int general_timeout;
	unsigned int max_headers;
	unsigned int max_header_bytes;
	olong max_content_bytes;
	Frame::Ptr frame;
	SessionStats::Ptr stats;
      };

      struct Host {
	std::string host;
	std::string cn;     // host for CN verification, defaults to host if empty
	std::string head;   // host to send in HTTP header, defaults to host if empty
	std::string port;

	const std::string& host_transport() const
	{
	  return host;
	}

	const std::string& host_cn() const
	{
	  return cn.empty() ? host : cn;
	}

	const std::string& host_head() const
	{
	  return head.empty() ? host : head;
	}
      };

      struct Request {
	std::string method;
	std::string uri;
	std::string username;
	std::string password;
      };

      struct ContentInfo {
	enum {
	  // content length if Transfer-Encoding: chunked
	  CHUNKED=-1
	};

	ContentInfo()
	  : length(0),
	    keepalive(false) {}

	std::string type;
	std::string content_encoding;
	olong length;
	bool keepalive;
      };

      class HTTPCore : public RC<thread_unsafe_refcount>
      {
	// calls tcp_* handlers
	friend class TCPTransport::Link<HTTPCore*, false>;

	typedef TCPTransport::Link<HTTPCore*, false> LinkImpl;

	typedef AsioDispatchResolve<HTTPCore,
				    void (HTTPCore::*)(const boost::system::error_code&,
						   boost::asio::ip::tcp::resolver::iterator),
				    boost::asio::ip::tcp::resolver::iterator> AsioDispatchResolveTCP;

	class ChunkedHelper : public RC<thread_unsafe_refcount>
	{
	  enum State {
	    hex,
	    post_hex,
	    post_hex_lf,
	    post_chunk_cr,
	    post_chunk_lf,
	    post_content_cr,
	    post_content_lf,
	    done,
	    chunk,
	  };

	public:
	  typedef boost::intrusive_ptr<ChunkedHelper> Ptr;

	  ChunkedHelper()
	    : state(hex),
	      size(0)
	  {
	  }

	  bool receive(HTTPCore* parent, BufferAllocated& buf)
	  {
	    while (buf.defined())
	      {
		if (state == chunk)
		  {
		    if (size)
		      {
			if (buf.size() <= size)
			  {
			    size -= buf.size();
			    parent->do_http_content_in(buf);
			    break;
			  }
			else
			  {
			    BufferAllocated content(buf.read_alloc(size), size, 0);
			    size = 0;
			    parent->do_http_content_in(content);
			  }
		      }
		    else
		      state = post_chunk_cr;
		  }
		else if (state == done)
		  break;
		else
		  {
		    const char c = char(buf.pop_front());
		  reprocess:
		    switch (state)
		      {
		      case hex:
			{
			  const int v = parse_hex_char(c);
			  if (v >= 0)
			    size = (size << 4) + v;
			  else
			    {
			      state = post_hex;
			      goto reprocess;
			    }
			}
			break;
		      case post_hex:
			if (c == '\r')
			  state = post_hex_lf;
			break;
		      case post_hex_lf:
			if (c == '\n')
			  {
			    if (size)
			      state = chunk;
			    else
			      state = post_content_cr;
			  }
			else
			  {
			    state = post_hex;
			    goto reprocess;
			  }
			break;
		      case post_chunk_cr:
			if (c == '\r')
			  state = post_chunk_lf;
			break;
		      case post_chunk_lf:
			if (c == '\n')
			  state = hex;
			else
			  {
			    state = post_chunk_cr;
			    goto reprocess;
			  }
			break;
		      case post_content_cr:
			if (c == '\r')
			  state = post_content_lf;
			break;
		      case post_content_lf:
			if (c == '\n')
			  state = done;
			else
			  {
			    state = post_content_cr;
			    goto reprocess;
			  }
			break;
		      default: // should never be reached
			break;
		      }
		  }
	      }
	    return state == done;
	  }

	  static BufferPtr transmit(BufferPtr buf)
	  {
	    const size_t headroom = 24;
	    const size_t tailroom = 16;
	    static const char crlf[] = "\r\n";

	    if (!buf || buf->offset() < headroom || buf->remaining() < tailroom)
	      {
		// insufficient headroom/tailroom, must realloc
		Frame::Context fc(headroom, 0, tailroom, 0, sizeof(size_t), 0);
		buf = fc.copy(buf);
	      }

	    size_t size = buf->size();
	    buf->prepend((unsigned char *)crlf, 2);
	    if (size)
	      {
		while (size)
		  {
		    char *pc = (char *)buf->prepend_alloc(1);
		    *pc = render_hex_char(size & 0xF);
		    size >>= 4;
		  }
	      }
	    else
	      {
		char *pc = (char *)buf->prepend_alloc(1);
		*pc = '0';
	      }
	    buf->write((unsigned char *)crlf, 2);
	    return buf;
	  }

	private:
	  State state;
	  size_t size;
	};

      public:
	typedef boost::intrusive_ptr<HTTPCore> Ptr;

	HTTPCore(boost::asio::io_service& io_service_arg,
	     const Config::Ptr& config_arg)
	  : io_service(io_service_arg),
	    halt(false),
	    ready(true),
	    alive(false),
	    config(config_arg),
	    socket(io_service_arg),
	    resolver(io_service_arg),
	    connect_timer(io_service_arg),
	    general_timer(io_service_arg),
	    frame(config_arg->frame),
	    stats(config_arg->stats)
	{
	  per_request_reset();
	}

	void reset()
	{
	  if (halt)
	    {
	      halt = false;
	      ready = true;
	    }
	}

	void start_request()
	{
	  if (!is_ready())
	    throw http_client_exception("not ready");
	  ready = false;
	  io_service.post(asio_dispatch_post(&HTTPCore::handle_request, this));
	}

	void stop()
	{
	  if (!halt)
	    {
	      halt = true;
	      ready = false;
	      alive = false;
	      if (link)
		link->stop();
	      socket.close();
	      resolver.cancel();
	      general_timer.cancel();
	      connect_timer.cancel();
	    }
	}

	bool is_ready() const {
	  return !halt && ready;
	}

	const HTTP::Reply& reply() const {
	  return reply_obj;
	}

	const HTTP::HeaderList& headers() const {
	  return reply_obj.headers;
	}

	const olong content_length() const {
	  return reply_content_length;
	}

	std::string ssl_handshake_details() const {
	  if (ssl_sess)
	    return ssl_sess->ssl_handshake_details();
	  else
	    return "";
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

	virtual void http_headers_received()
	{
	}

	virtual void http_headers_sent(const Buffer& buf)
	{
	}

	virtual void http_content_in(BufferAllocated& buf) = 0;

	virtual void http_done(const int status, const std::string& description) = 0;

	virtual void http_keepalive_close(const int status, const std::string& description)
	{
	}

      private:
	void verify_frame()
	{
	  if (!frame)
	    throw http_client_exception("frame undefined");
	}

	size_t http_buf_size() const
	{
	  return (*frame)[Frame::WRITE_HTTP].payload();
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
	    if (config->general_timeout)
	      {
		general_timer.expires_at(now + Time::Duration::seconds(config->general_timeout));
		general_timer.async_wait(asio_dispatch_timer(&HTTPCore::general_timeout_handler, this));
	      }

	    if (alive)
	      {
		generate_request();
	      }
	    else
	      {
		host = http_host();
		if (host.port.empty())
		  host.port = config->ssl_factory ? "443" : "80";

		if (config->ssl_factory)
		  ssl_sess = config->ssl_factory->ssl(host.host_cn());

		if (config->connect_timeout)
		  {
		    connect_timer.expires_at(now + Time::Duration::seconds(config->connect_timeout));
		    connect_timer.async_wait(asio_dispatch_timer(&HTTPCore::connect_timeout_handler, this));
		  }

		boost::asio::ip::tcp::resolver::query query(host.host_transport(), host.port);
		resolver.async_resolve(query, AsioDispatchResolveTCP(&HTTPCore::handle_resolve, this));
	      }
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("handle_request", e);
	    }
	}

	void handle_resolve(const boost::system::error_code& error, // called by Asio
			    boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
	  if (halt)
	    return;

	  if (error)
	    {
	      asio_error_handler(E_RESOLVE, "handle_resolve", error);
	      return;
	    }

	  try {
	    boost::asio::async_connect(socket,
				       endpoint_iterator,
				       asio_dispatch_composed_connect(&HTTPCore::handle_connect, this));
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("handle_resolve", e);
	    }
	}

	void handle_connect(const boost::system::error_code& error, // called by Asio
			    boost::asio::ip::tcp::resolver::iterator iterator)
	{
	  if (halt)
	    return;

	  if (error)
	    {
	      asio_error_handler(E_CONNECT, "handle_connect", error);
	      return;
	    }

	  try {
	    connect_timer.cancel();
	    set_default_stats();
	    link.reset(new LinkImpl(this,
				    socket,
				    0, // send_queue_max_size (unlimited)
				    8, // free_list_max_size
				    (*frame)[Frame::READ_LINK_TCP],
				    stats));
	    link->set_raw_mode(true);
	    link->start();

	    if (ssl_sess)
	      ssl_sess->start_handshake();

	    // xmit the request
	    generate_request();
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("handle_connect", e);
	    }
	}

	// error notification
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

	void general_timeout_handler(const boost::system::error_code& e) // called by Asio
	{
	  if (!halt && !e)
	    error_handler(E_GENERAL_TIMEOUT, "General timeout");
	}

	void connect_timeout_handler(const boost::system::error_code& e) // called by Asio
	{
	  if (!halt && !e)
	    error_handler(E_CONNECT_TIMEOUT, "Connect timeout");
	}

	void set_default_stats()
	{
	  if (!stats)
	    stats.reset(new SessionStats());
	}

	void per_request_reset()
	{
	  reply_obj.reset();
	  reply_status = HTTP::ReplyParser::pending;
	  reply_parser.reset();
	  reply_header_bytes = 0;
	  reply_content_length = 0;
	  reply_content_bytes = 0;
	  reply_chunked.reset();
	  out_eof = false;
	}

	void generate_request()
	{
	  per_request_reset();

	  const Request req = http_request();
	  content_info = http_content_info();

	  outbuf.reset(new BufferAllocated(4096, BufferAllocated::GROW));
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
	  if (!content_info.content_encoding.empty())
	    os << "Content-Encoding: " << content_info.content_encoding << "\r\n";
	  if (content_info.keepalive)
	    os << "Connection: keep-alive\r\n";
	  os << "Accept: */*\r\n";
	  os << "\r\n";

	  http_headers_sent(*outbuf);
	  http_out();
	}

	static olong get_content_length(const HTTP::HeaderList& headers)
	{
	  const std::string transfer_encoding = headers.get_value_trim("transfer-encoding");
	  if (!string::strcasecmp(transfer_encoding, "chunked"))
	    {
	      return ContentInfo::CHUNKED;
	    }
	  else
	    {
	      const std::string content_length_str = headers.get_value_trim("content-length");
	      if (content_length_str.empty())
		return 0;
	      const olong content_length = parse_number_throw<olong>(content_length_str, "content-length");
	      if (content_length < 0)
		throw http_client_exception("content-length is < 0");
	      return content_length;
	    }
	}

	// Transmit outgoing HTTP, either to SSL object (HTTPS) or TCP socket (HTTP)
	void http_out()
	{
	  if (halt)
	    return;
	  if ((!outbuf || outbuf->empty()) && !out_eof)
	    {
	      outbuf = http_content_out();
	      if (!outbuf || !outbuf->defined())
		out_eof = true;
	      if (content_info.length == ContentInfo::CHUNKED)
		outbuf = ChunkedHelper::transmit(outbuf);
	    }
	  if (outbuf)
	    {
	      const size_t size = std::min(outbuf->size(), http_buf_size());
	      if (size)
		{
		  if (ssl_sess)
		    {
		      // HTTPS: send outgoing cleartext HTTP data from request to SSL object
		      ssize_t actual = 0;
		      try {
			actual = ssl_sess->write_cleartext_unbuffered(outbuf->data(), size);
		      }
		      catch (...)
			{
			  stats->error(Error::SSL_ERROR);
			  throw;
			}
		      if (actual >= 0)
			{
#if defined(OPENVPN_DEBUG_HTTPCLI)
			  BufferAllocated tmp(outbuf->c_data(), actual, 0);
			  OPENVPN_LOG(buf_to_string(tmp));
#endif
			  outbuf->advance(actual);
			}
		      else if (actual == SSLConst::SHOULD_RETRY)
			;
		      else
			throw http_client_exception("unknown write status from SSL layer");
		      ssl_down_stack();
		    }
		  else
		    {
		      // HTTP: send outgoing cleartext HTTP data from request to TCP socket
		      BufferAllocated buf;
		      frame->prepare(Frame::WRITE_HTTP, buf);
		      buf.write(outbuf->data(), size);
#if defined(OPENVPN_DEBUG_HTTPCLI)
		      OPENVPN_LOG(buf_to_string(buf));
#endif
		      if (link->send(buf))
			outbuf->advance(size);
		    }
		}
	    }
	}

	// Receive incoming HTTP
	void http_in(BufferAllocated& buf)
	{
	  if (halt || ready) // if ready, indicates unsolicited input
	    return;

	  if (reply_status == HTTP::ReplyParser::pending)
	    {
	      // processing HTTP reply and headers
	      for (size_t i = 0; i < buf.size(); ++i)
		{
		  reply_status = reply_parser.consume(reply_obj, (char)buf[i]);
		  if (reply_status == HTTP::ReplyParser::pending)
		    {
		      ++reply_header_bytes;
		      if ((reply_header_bytes & 0x3F) == 0)
			{
			  // only check header maximums once every 64 bytes
			  if ((config->max_header_bytes && reply_header_bytes > config->max_header_bytes)
			      || (config->max_headers && reply_obj.headers.size() > config->max_headers))
			    {
			      error_handler(E_HEADER_SIZE, "HTTP headers too large");
			      return;
			    }
			}
		    }
		  else
		    {
		      // finished processing HTTP reply and headers
		      buf.advance(i+1);
		      if (reply_status == HTTP::ReplyParser::success)
			{
			  reply_content_length = get_content_length(reply_obj.headers);
			  if (reply_content_length == ContentInfo::CHUNKED)
			    reply_chunked.reset(new ChunkedHelper());
			  if (!halt)
			    http_headers_received();
			  break;
			}
		      else
			{
			  error_handler(E_HTTP, "HTTP reply/headers parse error");
			  return;
			}
		    }
		}
	    }

	  if (reply_status == HTTP::ReplyParser::success)
	    {
	      // processing HTTP content
	      bool done = false;
	      if (reply_content_length >= 0)
		{
		  const olong needed = std::max(reply_content_length - reply_content_bytes, olong(0));
		  if (needed <= buf.size())
		    {
		      done = true;
		      if (needed < buf.size())
			buf.set_size(needed); // drop post-content residual data
		    }
		  do_http_content_in(buf);
		}
	      else if (reply_chunked)
		{
		  done = reply_chunked->receive(this, buf);
		}
	      if (done)
		do_http_done();
	    }
	}

	void do_http_content_in(BufferAllocated& buf)
	{
	  if (halt)
	    return;
	  if (buf.defined())
	    {
	      reply_content_bytes += buf.size();
	      if (config->max_content_bytes && reply_content_bytes > config->max_content_bytes)
		{
		  error_handler(E_CONTENT_SIZE, "HTTP content too large");
		  return;
		}
	      http_content_in(buf);
	    }
	}

	void http_eof(const int errcode, const std::string& err)
	{
	  error_handler(errcode, err);
	}

	void do_http_done()
	{
	  if (halt)
	    return;
	  if (content_info.keepalive)
	    {
	      general_timer.cancel();
	      alive = true;
	      ready = true;
	    }
	  else
	    stop();
	  http_done(E_SUCCESS, "Succeeded");
	}

	// read outgoing ciphertext data from SSL object and xmit to TCP socket
	void ssl_down_stack()
	{
	  while (!halt && ssl_sess->read_ciphertext_ready())
	    {
	      BufferPtr buf = ssl_sess->read_ciphertext();
	      link->send(*buf);
	    }
	}

	// read incoming cleartext data from SSL object and pass to HTTP receiver
	void ssl_up_stack()
	{
	  BufferAllocated buf;
	  while (!halt && ssl_sess->read_cleartext_ready())
	    {
	      frame->prepare(Frame::READ_SSL_CLEARTEXT, buf);
	      ssize_t size = 0;
	      try {
		size = ssl_sess->read_cleartext(buf.data(), buf.max_size());
	      }
	      catch (...)
		{
		  stats->error(Error::SSL_ERROR);
		  throw;
		}
	      if (size >= 0)
		{
		  buf.set_size(size);
		  http_in(buf);
		}
	      else if (size == SSLConst::SHOULD_RETRY)
		break;
	      else if (size == SSLConst::PEER_CLOSE_NOTIFY)
		http_eof(E_EOF_SSL, "SSL PEER_CLOSE_NOTIFY");
	      else
		throw http_client_exception("unknown read status from SSL layer");
	    }
	}

	void tcp_read_handler(BufferAllocated& b) // called by LinkImpl
	{
	  if (halt)
	    return;

	  try {
	    if (ssl_sess)
	      {
		// HTTPS
		BufferPtr buf(new BufferAllocated());
		buf->swap(b); // take ownership
		ssl_sess->write_ciphertext(buf);
		ssl_up_stack();

		// In some cases, such as immediately after handshake,
		// a write becomes possible after a read has completed.
		http_out();
	      }
	    else
	      {
		// HTTP
		http_in(b);
	      }
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("tcp_read_handler", e);
	    }
	}

	void tcp_write_queue_empty() // called by LinkImpl
	{
	  if (halt)
	    return;

	  try {
	    http_out();
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("tcp_write_queue_empty", e);
	    }

	}

	void tcp_eof_handler() // called by LinkImpl
	{
	  if (halt)
	    return;

	  try {
	    http_eof(E_EOF_TCP, "TCP EOF");
	    return;
	  }
	  catch (const std::exception& e)
	    {
	      handle_exception("tcp_eof_handler", e);
	    }
	}

	void tcp_error_handler(const char *error) // called by LinkImpl
	{
	  if (halt)
	    return;
	  error_handler(E_TCP, std::string("HTTPCore TCP: ") + error);
	}

	void asio_error_handler(int errcode, const char *func_name, const boost::system::error_code& error)
	{
	  error_handler(errcode, std::string("HTTPCore Asio ") + func_name + ": " + error.message());
	}

	void handle_exception(const char *func_name, const std::exception& e)
	{
	  error_handler(E_EXCEPTION, std::string("HTTPCore Exception ") + func_name + ": " + e.what());
	}

	boost::asio::io_service& io_service;

	bool halt;
	bool ready;
	bool alive;

	Config::Ptr config;

	boost::asio::ip::tcp::socket socket;
	boost::asio::ip::tcp::resolver resolver;

	SSLAPI::Ptr ssl_sess;

	Host host;
	ContentInfo content_info;

	HTTP::Reply reply_obj;
	HTTP::ReplyParser::status reply_status;
	HTTP::ReplyParser reply_parser;
	unsigned int reply_header_bytes;
	olong reply_content_length;  // Content-Length in header
	olong reply_content_bytes;
	ChunkedHelper::Ptr reply_chunked;

	LinkImpl::Ptr link;

	BufferPtr outbuf;
	bool out_eof;

	AsioTimer connect_timer;
	AsioTimer general_timer;

	Frame::Ptr frame;
	SessionStats::Ptr stats;
      };

      template <typename PARENT>
      class HTTPDelegate : public HTTPCore
      {
      public:
	OPENVPN_EXCEPTION(http_delegate_error);

	typedef boost::intrusive_ptr<HTTPDelegate> Ptr;

	HTTPDelegate(boost::asio::io_service& io_service,
		     const WS::Client::Config::Ptr& config,
		     PARENT* parent_arg)
	  : WS::Client::HTTPCore(io_service, config),
	    parent(parent_arg)
	{
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

	void detach()
	{
	  if (parent)
	    {
	      parent = NULL;
	      stop();
	    }
	}

      private:
	PARENT* parent;
      };
    }
  }
}

#endif
