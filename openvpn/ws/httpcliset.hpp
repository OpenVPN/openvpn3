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

#ifndef OPENVPN_WS_HTTPCLISET_H
#define OPENVPN_WS_HTTPCLISET_H

#include <string>
#include <sstream>
#include <ostream>
#include <vector>
#include <memory>
#include <utility>
#include <algorithm>
#include <functional>
#include <limits>
#include <unordered_map>
#include <thread>

#include <openvpn/time/asiotimer.hpp>
#include <openvpn/buffer/buflist.hpp>
#include <openvpn/buffer/bufstr.hpp>
#include <openvpn/buffer/zlib.hpp>
#include <openvpn/random/randint.hpp>
#include <openvpn/http/urlparse.hpp>
#include <openvpn/ws/httpcli.hpp>

#ifndef OPENVPN_HTTP_CLISET_RC
#define OPENVPN_HTTP_CLISET_RC RC<thread_unsafe_refcount>
#endif

namespace openvpn {
  namespace WS {

    class ClientSet : public RC<thread_unsafe_refcount>
    {
      class Client;

    public:
      typedef RCPtr<ClientSet> Ptr;

      typedef WS::Client::HTTPDelegate<Client> HTTPDelegate;

      class HTTPStateContainer
      {
      public:
	void reset()
	{
	  http.reset();
	}

	bool alive() const
	{
	  return http && http->is_alive();
	}

      private:
	friend Client;

	void attach(Client* parent)
	{
	  http->attach(parent);
	}

	void close(const bool keepalive)
	{
	  if (http)
	    {
	      http->detach(keepalive);
	      if (!keepalive)
		http.reset();
	    }
	}

	void construct(asio::io_context& io_context,
		       const WS::Client::Config::Ptr& config)
	{
	  http.reset(new HTTPDelegate(io_context, config, nullptr));
	}

	void start_request()
	{
	  http->start_request();
	}

	HTTPDelegate::Ptr http;
      };

      class TransactionSet;

      struct Transaction
      {
	static constexpr int UNDEF = -1;

	std::string url(const TransactionSet& ts) const
	{
	  URL::Parse u = URL::Parse::from_components(bool(ts.http_config->ssl_factory),
						     ts.host.host,
						     ts.host.port,
						     req.uri);
	  return u.to_string();
	}

	std::string title(const TransactionSet& ts) const
	{
	  return req.method + ' ' + url(ts);
	}

	void compress_content_out(const unsigned int min_size=64,
				  const bool verbose=OPENVPN_GZIP_VERBOSE)
	{
#ifdef HAVE_ZLIB
	  if (content_out.join_size() >= min_size)
	    {
	      BufferPtr co = content_out.join();
	      content_out.clear();
	      co = ZLib::compress_gzip(co, 0, 0, 1, verbose);
	      ci.length = co->size();
	      content_out.push_back(std::move(co));
	      ci.content_encoding = "gzip";
	    }
#endif
	}

	// input
	WS::Client::Request req;
	WS::Client::ContentInfo ci;
	BufferList content_out;
	bool accept_gzip_in = false;
	bool randomize_resolver_results = false;

	// output
	int status = UNDEF;
	std::string description;
	HTTP::Reply reply;
	BufferList content_in;

	void dump(std::ostream& os, const TransactionSet& ts) const
	{
	  os << "----- " << format_status(ts) << " -----\n";
	  BufferPtr in = content_in.join();
	  const std::string s = buf_to_string(*in);
	  os << s;
	  if (!s.empty() && !string::ends_with_newline(s))
	    os << '\n';
	}

	std::string content_in_string() const
	{
	  BufferPtr in = content_in.join();
	  return buf_to_string(*in);
	}

	std::string format_status(const TransactionSet& ts) const
	{
	  std::string ret;
	  ret.reserve(256);
	  ret += title(ts);
	  ret += " : ";
	  if (status == WS::Client::Status::E_SUCCESS)
	    {
	      ret += std::to_string(reply.status_code);
	      ret += ' ';
	      ret += reply.status_text;
	    }
	  else
	    {
	      ret += WS::Client::Status::error_str(status);
	      ret += ' ';
	      ret += description;
	    }
	  return ret;
	}
      };

      class TransactionSet : public RC<thread_unsafe_refcount>
      {
      public:
	typedef RCPtr<TransactionSet> Ptr;
	typedef std::vector<std::unique_ptr<Transaction>> Vector;

	// configuration
	WS::Client::Config::Ptr http_config;
	WS::Client::Host host;
	unsigned int max_retries = 1;
	int debug_level = 2;
	Time::Duration delayed_start;
	Time::Duration retry_duration = Time::Duration::seconds(5);

	// request/response vector
	Vector transactions;

	// true if all requests were successful
	bool status = false;

	// completion method
	std::function<void(TransactionSet& ts)> completion;

	// post-connect method, useful to validate server
	// on local sockets
	std::function<void(TransactionSet& ts, AsioPolySock::Base& sock)> post_connect;

	// Enable preserve_http_state to reuse HTTP session
	// across multiple completions.
	// hsc.reset() can be called to explicitly
	// close persistent state.
	bool preserve_http_state = false;
	HTTPStateContainer hsc;

	// Return true if and only if all HTTP transactions
	// succeeded AND each HTTP status code was in the
	// successful range of 2xx.
	bool http_status_success() const
	{
	  if (!status)
	    return false;
	  if (transactions.empty())
	    return false;
	  for (auto &t : transactions)
	    {
	      if (t->status != WS::Client::Status::E_SUCCESS)
		return false;
	      if (t->reply.status_code < 200 || t->reply.status_code >= 300)
		return false;
	    }
	  return true;
	}

	void dump(std::ostream& os, const bool content_only=false) const
	{
	  for (auto &t : transactions)
	    {
	      if (content_only)
		os << t->content_in_string();
	      else
		t->dump(os, *this);
	    }
	}
      };

      ClientSet(asio::io_context& io_context_arg)
	: io_context(io_context_arg),
	  halt(false),
	  next_id(0)
      {
      }

      void set_random(RandomAPI& rand)
      {
	randint.reset(new RandomInt(rand));
      }

      void new_request(const TransactionSet::Ptr& ts)
      {
	const client_t id = new_client_id();
	Client::Ptr cli = new Client(this, ts, id);
	clients[id] = cli;
	cli->start();
      }

      static void new_request_synchronous(const TransactionSet::Ptr& ts)
      {
	Log::Context::Wrapper logwrap;
	std::thread mythread([&ts, &logwrap]() {
	    Log::Context logctx(logwrap);
	    asio::io_context io_context(1); // concurrency hint=1
	    ClientSet::Ptr cs;
	    try {
	      cs.reset(new ClientSet(io_context));
	      cs->new_request(ts);
	      io_context.run();
	    }
	    catch (...)
	      {
		if (cs)
		  cs->stop();        // on exception, stop ClientSet
		io_context.poll();   // execute completion handlers
	      }
	  });
	mythread.join();
      }

      void stop()
      {
	if (halt)
	  return;
	halt = true;
	for (auto &c : clients)
	  c.second->stop(false);
      }

    private:
      typedef unsigned int client_t;

      class Client : public OPENVPN_HTTP_CLISET_RC
      {
      public:
	typedef RCPtr<Client> Ptr;
	friend HTTPDelegate;

	Client(ClientSet* parent_arg,
	       const TransactionSet::Ptr& ts_arg,
	       client_t client_id_arg)
	  : parent(parent_arg),
	    ts(ts_arg),
	    n_retries(0),
	    reconnect_timer(parent_arg->io_context),
	    client_id(client_id_arg),
	    halt(false),
	    started(false)
	{
	}

	bool start()
	{
	  if (started || halt)
	    return false;
	  started = true;
	  ts->status = false;
	  ts_iter = ts->transactions.begin();
	  if (ts->delayed_start.defined())
	    {
	      retry_duration = ts->delayed_start;
	      reconnect_schedule();
	    }
	  else
	    {
	      next_request();
	    }
	  return true;
	}

	void stop(const bool keepalive)
	{
	  if (halt)
	    return;
	  halt = true;
	  reconnect_timer.cancel();
	  close_http(keepalive);
	}

      private:
	void close_http(const bool keepalive)
	{
	  ts->hsc.close(keepalive);
	}

	void remove_self_from_map()
	{
	  asio::post(parent->io_context, [id=client_id, parent=ClientSet::Ptr(parent)]()
		     {
		       parent->remove_client_id(id);
		     });
	}

	bool check_if_done()
	{
	  if (ts_iter == ts->transactions.end())
	    {
	      done(true);
	      return true;
	    }
	  else
	    return false;
	}

	void done(const bool status)
	{
	  stop(status);
	  remove_self_from_map();
	  ts->status = status;
	  if (!ts->preserve_http_state)
	    ts->hsc.reset();
	  if (ts->completion)
	    ts->completion(*ts);
	}

	Transaction& trans()
	{
	  return **ts_iter;
	}

	const Transaction& trans() const
	{
	  return **ts_iter;
	}

	std::string title() const
	{
	  return trans().title(*ts);
	}

	void next_request()
	{
	  if (check_if_done())
	    return;
	  if (!ts->hsc.alive())
	    ts->hsc.construct(parent->io_context, ts->http_config);
	  ts->hsc.attach(this);
	  retry_duration = ts->retry_duration;

	  // get current transaction
	  Transaction& t = trans();

	  // set up content out iterator
	  out_iter = t.content_out.begin();

	  // init buffer to receive content in
	  t.content_in.clear();

	  ts->hsc.start_request();
	}

	void reconnect_schedule()
	{
	  if (check_if_done())
	    return;
	  reconnect_timer.expires_at(Time::now() + retry_duration);
	  reconnect_timer.async_wait([self=Ptr(this)](const asio::error_code& error)
				     {
				       if (!error)
					 self->reconnect_callback(error);
				     });
	}

	void reconnect_callback(const asio::error_code& e)
	{
	  if (!halt && !e)
	    next_request();
	}

	WS::Client::Host http_host(HTTPDelegate& hd) const
	{
	  return ts->host;
	}

	WS::Client::Request http_request(HTTPDelegate& hd) const
	{
	  return trans().req;
	}

	WS::Client::ContentInfo http_content_info(HTTPDelegate& hd) const
	{
	  const Transaction& t = trans();
	  WS::Client::ContentInfo ci = t.ci;
	  if (!ci.length)
	    ci.length = t.content_out.join_size();
#ifdef HAVE_ZLIB
	  if (t.accept_gzip_in)
	    ci.extra_headers.emplace_back("Accept-Encoding: gzip");
#endif
	  return ci;
	}

	void http_headers_received(HTTPDelegate& hd)
	{
	  if (ts->debug_level >= 2)
	    {
	      std::ostringstream os;
	      os << "----- HEADERS RECEIVED -----\n";
	      os << "    " << title() << '\n';
	      os << "    ENDPOINT: " << hd.remote_endpoint_str() << '\n';
	      os << "    HANDSHAKE_DETAILS: " << hd.ssl_handshake_details() << '\n';
	      os << "    CONTENT-LENGTH: " << hd.content_length() << '\n';
	      os << "    HEADERS: " << string::indent(hd.reply().to_string(), 0, 13) << '\n';
	      OPENVPN_LOG_STRING(os.str());
	    }

	  Transaction& t = trans();

	  // save reply
	  t.reply = hd.reply();
	}

	BufferPtr http_content_out(HTTPDelegate& hd)
	{
	  if (out_iter != trans().content_out.end())
	    {
	      BufferPtr ret = new BufferAllocated(**out_iter);
	      ++out_iter;
	      return ret;
	    }
	  else
	    return BufferPtr();
	}

	void http_content_out_needed(HTTPDelegate& hd)
	{
	}

	void http_headers_sent(HTTPDelegate& hd, const Buffer& buf)
	{
	  if (ts->debug_level >= 2)
	    {
	      std::ostringstream os;
	      os << "----- HEADERS SENT -----\n";
	      os << "    " << title() << '\n';
	      os << "    ENDPOINT: " << hd.remote_endpoint_str() << '\n';
	      os << "    HEADERS: " << string::indent(buf_to_string(buf), 0, 13) << '\n';
	      OPENVPN_LOG_STRING(os.str());
	    }
	}

	void http_mutate_resolver_results(HTTPDelegate& hd, asio::ip::tcp::resolver::results_type& results)
	{
	  if (parent->randint && trans().randomize_resolver_results)
	    results.randomize((*parent->randint)());
	}

	void http_content_in(HTTPDelegate& hd, BufferAllocated& buf)
	{
	  if (buf.defined())
	    trans().content_in.emplace_back(new BufferAllocated(std::move(buf)));
	}

	void http_done(HTTPDelegate& hd, const int status, const std::string& description)
	{
	  Transaction& t = trans();
	  try {
	    // debug output
	    if (ts->debug_level >= 2)
	      {
		std::ostringstream os;
		os << "----- DONE -----\n";
		os << "    " << title() << '\n';
		os << "    STATUS: " << WS::Client::Status::error_str(status) << '\n';
		os << "    DESCRIPTION: " << description << '\n';
		OPENVPN_LOG_STRING(os.str());
	      }

	    // save status
	    t.status = status;
	    t.description = description;

	    if (status == WS::Client::Status::E_SUCCESS)
	      {
		// uncompress if server sent gzip-compressed data
		if (hd.reply().headers.get_value_trim("content-encoding") == "gzip")
		  {
#ifdef HAVE_ZLIB
		    BufferPtr bp = t.content_in.join();
		    t.content_in.clear();
		    bp = ZLib::decompress_gzip(std::move(bp), 0, 0, hd.http_config().max_content_bytes, ts->debug_level >= 2);
		    t.content_in.push_back(std::move(bp));
#else
		    throw Exception("gzip-compressed data returned from server but app not linked with zlib");
#endif
		  }

		// do next request
		++ts_iter;
		next_request();
	      }
	    else
	      {
		// failed
		if (++n_retries >= ts->max_retries)
		  {
		    // fail -- no more retries
		    done(false);
		  }
		else
		  {
		    // fail -- retry
		    close_http(false);
		    reconnect_schedule();
		  }
	      }
	  }
	  catch (const std::exception& e)
	    {
	      t.status = WS::Client::Status::E_EXCEPTION;
	      t.description = std::string("http_done: ") + e.what();
	      done(false);
	    }
	}

	void http_keepalive_close(HTTPDelegate& hd, const int status, const std::string& description)
	{
	  // this is a no-op because ts->hsc.alive() is always tested before construction
	}

	void http_post_connect(HTTPDelegate& hd, AsioPolySock::Base& sock)
	{
	  if (ts->post_connect)
	    ts->post_connect(*ts, sock);
	}

	ClientSet* parent;
	TransactionSet::Ptr ts;
	TransactionSet::Vector::const_iterator ts_iter;
	BufferList content_out;
	BufferList::const_iterator out_iter;
	unsigned int n_retries;
	Time::Duration retry_duration;
	AsioTimer reconnect_timer;
	client_t client_id;
	bool halt;
	bool started;
      };

      void remove_client_id(const client_t client_id)
      {
	auto e = clients.find(client_id);
	if (e != clients.end())
	  clients.erase(e);
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

      asio::io_context& io_context;
      bool halt;
      client_t next_id;
      std::unique_ptr<RandomInt> randint;
      std::unordered_map<client_t, Client::Ptr> clients;
    };

  }
}

#endif
