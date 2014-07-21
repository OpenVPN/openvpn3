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

// These classes handle parsing and representation of OpenVPN "remote" directives,
// and the list of IP addresses that they resolve to.
// <connection> blocks are supported.

#ifndef OPENVPN_CLIENT_REMOTELIST_H
#define OPENVPN_CLIENT_REMOTELIST_H

#include <string>
#include <sstream>
#include <vector>

#include <boost/asio.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/port.hpp>
#include <openvpn/common/asiodispatch.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/transport/protocol.hpp>
#include <openvpn/client/cliconstants.hpp>
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/random/randtype.hpp>

#if OPENVPN_DEBUG_REMOTELIST >= 1
#define OPENVPN_LOG_REMOTELIST(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_REMOTELIST(x)
#endif

namespace openvpn {

  class RemoteList : public RC<thread_unsafe_refcount>
  {
    // A single IP address that is part of a list of IP addresses
    // associated with a "remote" item.
    struct ResolvedAddr : public RC<thread_unsafe_refcount>
    {
      typedef boost::intrusive_ptr<ResolvedAddr> Ptr;
      IP::Addr addr;

      std::string to_string() const
      {
	return addr.to_string();
      }
    };

    // The IP address list associated with a single "remote" item.
    struct ResolvedAddrList : public std::vector<ResolvedAddr::Ptr>, public RC<thread_unsafe_refcount>
    {
      typedef boost::intrusive_ptr<ResolvedAddrList> Ptr;

      std::string to_string() const
      {
	std::string ret;
	for (std::vector<ResolvedAddr::Ptr>::const_iterator i = begin(); i != end(); ++i)
	  {
	    if (!ret.empty())
	      ret += ' ';
	    ret += (*i)->to_string();
	  }
	return ret;
      }
    };

    // A single "remote" item
    struct Item : public RC<thread_unsafe_refcount>
    {
      typedef boost::intrusive_ptr<Item> Ptr;

      // "remote" item parameters from config file
      std::string server_host;
      std::string server_port;
      Protocol transport_protocol;

      // IP address list defined after server_host is resolved
      ResolvedAddrList::Ptr res_addr_list;

      bool res_addr_list_defined() const
      {
	return res_addr_list && res_addr_list->size() > 0;
      }

      // cache a list of DNS-resolved IP addresses
      template <class EPITER>
      void set_endpoint_list(EPITER& endpoint_iterator)
      {
	EPITER end;
	res_addr_list.reset(new ResolvedAddrList());
	while (endpoint_iterator != end)
	  {
	    ResolvedAddr::Ptr addr(new ResolvedAddr());
	    addr->addr = IP::Addr::from_asio(endpoint_iterator->endpoint().address());
	    res_addr_list->push_back(addr);
	    ++endpoint_iterator;
	  }
	OPENVPN_LOG_REMOTELIST("*** RemoteList::Item endpoint SET " << to_string());
      }

      // get an endpoint for contacting server
      template <class EP>
      bool get_endpoint(EP& endpoint, const size_t index) const
      {
	if (res_addr_list && index < res_addr_list->size())
	  {
	    endpoint.address((*res_addr_list)[index]->addr.to_asio());
	    endpoint.port(parse_number_throw<unsigned int>(server_port, "remote_port"));
	    OPENVPN_LOG_REMOTELIST("*** RemoteList::Item endpoint GET[" << index << "] " << endpoint << ' ' << to_string());
	    return true;
	  }
	else
	  return false;
      }

      std::string to_string() const
      {
	std::ostringstream out;
	out << "host=" << server_host;
	if (res_addr_list)
	  out << '[' << res_addr_list->to_string() << ']';
	out << " port=" << server_port
	    << " proto=" << transport_protocol.str();
	return out.str();
      }
    };

    // Used to index into remote list.
    // The primary index is the remote list index.
    // The secondary index is the index into the
    // Item's IP address list (res_addr_list).
    class Index
    {
    public:
      Index()
      {
	reset();
      }

      void reset()
      {
	primary_ = secondary_ = 0;
      }

      void reset_secondary()
      {
	secondary_ = 0;
      }

      bool increment(const size_t pri_len, const size_t sec_len)
      {
	if (++secondary_ >= sec_len)
	  {
	    secondary_ = 0;
	    if (++primary_ >= pri_len)
	      primary_ = 0;
	    return true;
	  }
	else
	  return false;
      }

      bool equals(const Index& other) const
      {
	return primary_ == other.primary_ && secondary_ == other.secondary_;
      }

      size_t primary() const { return primary_; }
      size_t secondary() const { return secondary_; }

    private:
      size_t primary_;
      size_t secondary_;
    };

  public:
    // Used for errors occurring after initial options processing,
    // and generally indicate logic errors
    // (option_error used during initial options processing).
    OPENVPN_EXCEPTION(remote_list_error);

    typedef boost::intrusive_ptr<RemoteList> Ptr;

    // Helper class used to pre-resolve all items in remote list.
    // This is useful in tun_persist mode, where it may be necessary
    // to pre-resolve all potential remote server items prior
    // to initial tunnel establishment.
    class PreResolve : public RC<thread_unsafe_refcount>
    {
      typedef AsioDispatchResolve<PreResolve,
				  void (PreResolve::*)(const boost::system::error_code&,
						       boost::asio::ip::tcp::resolver::iterator),
				  boost::asio::ip::tcp::resolver::iterator> AsioDispatchResolveTCP;

    public:
      typedef boost::intrusive_ptr<PreResolve> Ptr;

      struct NotifyCallback
      {
	// client callback when resolve operation is complete
	virtual void pre_resolve_done() = 0;
      };

      PreResolve(boost::asio::io_service& io_service_arg,
		 const RemoteList::Ptr& remote_list_arg,
		 const SessionStats::Ptr& stats_arg)
	:  io_service(io_service_arg),
	   resolver(io_service_arg),
	   notify_callback(NULL),
	   remote_list(remote_list_arg),
	   stats(stats_arg),
	   index(0)
      {
      }

      bool work_available() const
      {
	return remote_list->defined() && remote_list->enable_cache;
      }

      void start(NotifyCallback* notify_callback_arg)
      {
	if (notify_callback_arg)
	  {
	    // This method is a no-op (i.e. pre_resolve_done is called immediately)
	    // if caching not enabled in underlying remote_list or if start() was
	    // previously called and is still in progress.
	    if (!notify_callback && work_available())
	      {
		notify_callback = notify_callback_arg;
		remote_list->index.reset();
		index = 0;
		next();
	      }
	    else
	      notify_callback_arg->pre_resolve_done();
	  }
      }

      void cancel()
      {
	notify_callback = NULL;
	index = 0;
	resolver.cancel();
      }

    private:
      void next()
      {
	while (index < remote_list->list.size())
	  {
	    Item& item = *remote_list->list[index];

	    // try to resolve item if no cached data present
	    if (!item.res_addr_list_defined())
	      {
		// next item to resolve
		const Item* sitem = remote_list->search_server_host(item.server_host);
		if (sitem)
		  {
		    // item's server_host matches one previously resolved -- use it
		    OPENVPN_LOG_REMOTELIST("*** PreResolve USED CACHE for " << item.server_host);
		    item.res_addr_list = sitem->res_addr_list;
		  }
		else
		  {
		    // call into Asio to do the resolve operation
		    OPENVPN_LOG_REMOTELIST("*** PreResolve RESOLVE on " << item.server_host);
		    boost::asio::ip::tcp::resolver::query query(item.server_host, "0");
		    resolver.async_resolve(query, AsioDispatchResolveTCP(&PreResolve::resolve_callback, this));
		    return;
		  }
	      }
	    ++index;
	  }

	// Done resolving list.  Prune out all entries we were unable to
	// resolve unless doing so would result in an empty list.
	// Then call client's callback method.
	{
	  NotifyCallback* ncb = notify_callback;
	  if (remote_list->cached_item_exists())
	    remote_list->prune_uncached();
	  cancel();
	  ncb->pre_resolve_done();
	}
      }

      // callback on resolve completion
      void resolve_callback(const boost::system::error_code& error,
			    boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
      {
	if (notify_callback && index < remote_list->list.size())
	  {
	    Item& item = *remote_list->list[index++];
	    if (!error)
	      {
		// resolve succeeded
		item.set_endpoint_list(endpoint_iterator);
	      }
	    else
	      {
		// resolve failed
		OPENVPN_LOG("DNS pre-resolve error on " << item.server_host << ": " << error.message());
		if (stats)
		  stats->error(Error::RESOLVE_ERROR);
	      }
	    next();
	  }
      }

      boost::asio::io_service& io_service;
      boost::asio::ip::tcp::resolver resolver;
      NotifyCallback* notify_callback;
      RemoteList::Ptr remote_list;
      SessionStats::Ptr stats;
      size_t index;
    };

    // create an empty remote list
    RemoteList()
    {
      init();
    }


    // create a remote list with exactly one item
    RemoteList(const std::string& server_host,
	       const std::string& server_port,
	       const Protocol& transport_protocol,
	       const std::string& title)
    {
      init();

      validate_port(server_port, title);

      Item::Ptr item(new Item());
      item->server_host = server_host;
      item->server_port = server_port;
      item->transport_protocol = transport_protocol;
      list.push_back(item);
    }

    // create a remote list from config file option list
    RemoteList(const OptionList& opt, bool warn)
    {
      init();

      // handle remote, port, and proto at the top-level
      Protocol default_proto(Protocol::UDPv4);
      std::string default_port = "1194";
      add(opt, default_proto, default_port);

      // cycle through <connection> blocks
      {
	const size_t max_conn_block_size = 4096;
	const OptionList::IndexList* conn = opt.get_index_ptr("connection");
	if (conn)
	  {
	    for (OptionList::IndexList::const_iterator i = conn->begin(); i != conn->end(); ++i)
	      {
		try {
		  const Option& o = opt[*i];
		  o.touch();
		  const std::string& conn_block_text = o.get(1, Option::MULTILINE);
		  OptionList::Limits limits("<connection> block is too large",
					    max_conn_block_size,
					    ProfileParseLimits::OPT_OVERHEAD,
					    ProfileParseLimits::TERM_OVERHEAD,
					    ProfileParseLimits::MAX_LINE_SIZE,
					    ProfileParseLimits::MAX_DIRECTIVE_SIZE);
		  const OptionList conn_block = OptionList::parse_from_config_static(conn_block_text, &limits);
		  Protocol proto(default_proto);
		  std::string port(default_port);

		  // unsupported options
		  if (warn)
		    {
		      unsupported_in_connection_block(conn_block, "http-proxy");
		      unsupported_in_connection_block(conn_block, "http-proxy-option");
		      unsupported_in_connection_block(conn_block, "http-proxy-user-pass");
		    }

		  add(conn_block, proto, port);
		}
		catch (Exception& e)
		  {
		    e.remove_label("option_error");
		    e.add_label("connection_block");
		    throw;
		  }
	      }
	  }
      }

      if (list.empty())
	throw option_error("remote option not specified");

      //OPENVPN_LOG(to_string());
    }

    // if cache is enabled, all DNS names will be preemptively queried
    void set_enable_cache(const bool enable_cache_arg)
    {
      enable_cache = enable_cache_arg;
    }

    // override all server hosts to server_override
    void set_server_override(const std::string& server_override)
    {
      if (!server_override.empty())
	{
	  for (std::vector<Item::Ptr>::iterator i = list.begin(); i != list.end(); ++i)
	    {
	      Item& item = **i;
	      item.server_host = server_override;
	      item.res_addr_list.reset(NULL);	    
	    }
	  reset_items();
	}
    }

    // randomize item list, used to implement remote-random directive
    template <typename PRNG_TYPE>
    void randomize(PRNG_TYPE& prng)
    {
      for (size_t i = 0; i < list.size(); ++i)
	{
	  const size_t swapidx = i + rand_type<size_t, PRNG_TYPE>(prng) % (list.size() - i);
	  if (swapidx != i && swapidx < list.size())
	    list[i].swap(list[swapidx]);
	}
      index.reset();
    }

    // return true if at least one remote entry is of type proto
    bool contains_protocol(const Protocol& proto)
    {
      for (std::vector<Item::Ptr>::const_iterator i = list.begin(); i != list.end(); ++i)
	{
	  if (proto.transport_match((*i)->transport_protocol))
	    return true;
	}
      return false;
    }

    // Higher-level version of set_proto_override that also supports indication
    // on whether or not HTTP proxy is enabled.  Should be called after set_enable_cache
    // because it may modify enable_cache flag.
    void handle_proto_override(const Protocol& proto_override, const bool http_proxy_enabled)
    {
      if (http_proxy_enabled)
	{
	  const Protocol tcp(Protocol::TCP);
	  if (contains_protocol(tcp))
	      set_proto_override(tcp);
	  else
	    throw option_error("cannot connect via HTTP proxy because no TCP server entries exist in profile");
	}
      else if (proto_override.defined() && contains_protocol(proto_override))
	set_proto_override(proto_override);
    }

    // increment to next IP address
    void next()
    {
      if (index.increment(list.size(), secondary_length(index.primary())) && !enable_cache)
	reset_item(index.primary());
    }

    // Return details about current connection entry.
    // Return value is true if get_endpoint may be called
    // without raising an exception.
    bool endpoint_available(std::string* server_host, std::string* server_port, Protocol* transport_protocol) const
    {
      const Item& item = *list[primary_index()];
      if (server_host)
	*server_host = item.server_host;
      if (server_port)
	*server_port = item.server_port;
      const bool cached = (item.res_addr_list && index.secondary() < item.res_addr_list->size());
      if (transport_protocol)
	{
	  if (cached)
	    {
	      // Since we know whether resolved address is IPv4 or IPv6, add
	      // that info to the returned Protocol object.
	      Protocol proto(item.transport_protocol);
	      proto.mod_addr_version((*item.res_addr_list)[index.secondary()]->addr);
	      *transport_protocol = proto;
	    }
	  else
	    *transport_protocol = item.transport_protocol;
	}
      return cached;
    }

    // cache a list of DNS-resolved IP addresses
    template <class EPITER>
    void set_endpoint_list(EPITER& endpoint_iterator)
    {
      Item& item = *list[primary_index()];
      item.set_endpoint_list(endpoint_iterator);
      index.reset_secondary();
    }

    // get an endpoint for contacting server
    template <class EP>
    void get_endpoint(EP& endpoint) const
    {
      const Item& item = *list[primary_index()];
      if (!item.get_endpoint(endpoint, index.secondary()))
	throw remote_list_error("current remote server endpoint is undefined");
    }

    // return true if object has at least one connection entry
    bool defined() const { return list.size() > 0; }

    // return hostname (or IP address) of current connection entry
    const std::string& current_server_host() const
    {
      const Item& item = *list[primary_index()];
      return item.server_host;
    }

    // return transport protocol of current connection entry
    const Protocol& current_transport_protocol() const
    {
      const Item& item = *list[primary_index()];
      return item.transport_protocol;
    }

    // return hostname (or IP address) of first connection entry
    std::string first_server_host() const
    {
      const Item& item = *list[0];
      return item.server_host;
    }

    std::string to_string() const
    {
      std::ostringstream out;
      for (size_t i = 0; i < list.size(); ++i)
	{
	  const Item& e = *list[i];
	  out << '[' << i << "] " << e.to_string() << std::endl;
	}
      return out.str();
    }

  private:
    // initialization, called by constructors
    void init()
    {
      enable_cache = false;
    }

    // reset the cache associated with all items
    void reset_items()
    {
      for (std::vector<Item::Ptr>::iterator i = list.begin(); i != list.end(); ++i)
	(*i)->res_addr_list.reset(NULL);	    
      index.reset();
    }

    // reset the cache associated with a given item
    void reset_item(const size_t i)
    {
      if (i <= list.size())
	list[i]->res_addr_list.reset(NULL);
    }

    // return the current primary index (into list) and raise an exception
    // if it is undefined
    const size_t primary_index() const
    {
      const size_t pri = index.primary();
      if (pri < list.size())
	return pri;
      else
	throw remote_list_error("current remote server item is undefined");
    }

    // return the number of cached IP addresses associated with a given item
    size_t secondary_length(const size_t i) const
    {
      if (i < list.size())
	{
	  const Item& item = *list[i];
	  if (item.res_addr_list)
	    return item.res_addr_list->size();
	}
      return 0;
    }

    // Search for cached Item by server_host
    Item* search_server_host(const std::string& server_host)
    {
      for (std::vector<Item::Ptr>::iterator i = list.begin(); i != list.end(); ++i)
	{
	  Item* item = i->get();
	  if (server_host == item->server_host && item->res_addr_list_defined())
	    return item;
	}
      return NULL;
    }

    // prune remote entries so that only those of Protocol proto_override remain
    void set_proto_override(const Protocol& proto_override)
    {
      if (proto_override.defined())
	{
	  size_t di = 0;
	  for (size_t si = 0; si < list.size(); ++si)
	    {
	      const Item& item = *list[si];
	      if (proto_override.transport_match(item.transport_protocol))
		{
		  if (si != di)
		    list[di] = list[si];
		  ++di;
		}
	    }
	  if (di != list.size())
	    list.resize(di);
	  reset_items();
	}
    }

    // Return true if at least one cached Item exists
    bool cached_item_exists() const
    {
      for (std::vector<Item::Ptr>::const_iterator i = list.begin(); i != list.end(); ++i)
	{
	  const Item& item = **i;
	  if (item.res_addr_list_defined())
	    return true;
	}
      return false;
    }

    // Prune uncached Items so that only Items containing a res_addr_list with
    // size > 0 remain.
    void prune_uncached()
    {
      size_t di = 0;
      for (size_t si = 0; si < list.size(); ++si)
	{
	  const Item& item = *list[si];
	  if (item.res_addr_list_defined())
	    {
	      if (si != di)
		list[di] = list[si];
	      ++di;
	    }
	}
      if (di != list.size())
	list.resize(di);
      index.reset();
    }

    void add(const OptionList& opt, Protocol& default_proto, std::string& default_port)
    {
      // parse "proto" option if present
      {
	const Option* o = opt.get_ptr("proto");
	if (o)
	  default_proto = Protocol::parse(o->get(1, 16), true);
      }

      // parse "port" option if present
      {
	const Option* o = opt.get_ptr("port");
	if (o)
	  {
	    default_port = o->get(1, 16);
	    validate_port(default_port, "port");
	  }
      }

      // cycle through remote entries
      {
	const OptionList::IndexList* rem = opt.get_index_ptr("remote");
	if (rem)
	  {
	    for (OptionList::IndexList::const_iterator i = rem->begin(); i != rem->end(); ++i)
	      {
		Item::Ptr e(new Item());
		const Option& o = opt[*i];
		o.touch();
		e->server_host = o.get(1, 256);
		if (o.size() >= 3)
		  {
		    e->server_port = o.get(2, 16);
		    validate_port(e->server_port, "port");
		  }
		else
		  e->server_port = default_port;
		if (o.size() >= 4)
		  e->transport_protocol = Protocol::parse(o.get(3, 16), true);
		else
		  e->transport_protocol = default_proto;
		list.push_back(e);
	      }
	  }
      }
    }

    void unsupported_in_connection_block(const OptionList& options, const std::string& option)
    {
      if (options.exists(option))
	OPENVPN_LOG("NOTE: " << option << " directive is not currently supported in <connection> blocks");
    }

    bool enable_cache;
    Index index;

    std::vector<Item::Ptr> list;
  };

}

#endif
