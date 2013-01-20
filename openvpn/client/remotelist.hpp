//
//  remotelist.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// These classes handle parsing and representation of OpenVPN "remote" directives.
// <connection> blocks are supported.

#ifndef OPENVPN_CLIENT_REMOTELIST_H
#define OPENVPN_CLIENT_REMOTELIST_H

#include <string>
#include <sstream>
#include <vector>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/transport/protocol.hpp>
#include <openvpn/transport/endpoint_cache.hpp>
#include <openvpn/client/cliconstants.hpp>

namespace openvpn {

  class RemoteList : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<RemoteList> Ptr;

    struct Item
    {
      std::string server_host;
      std::string server_port;
      Protocol transport_protocol;

      std::string render() const
      {
	std::ostringstream out;
	out << "host=" << server_host
	    << " port=" << server_port
	    << " proto=" << transport_protocol.str();
	return out.str();
      }
    };

    RemoteList() {}

    RemoteList(const OptionList& opt)
    {
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
	OPENVPN_THROW(option_error, "remote option not specified");

      //OPENVPN_LOG(render());
    }

    // used to cycle through Item list
    Item get(unsigned int& index,
	     const std::string& server_override,
	     const Protocol& proto_override,
	     bool* proto_override_fail,
	     const EndpointCache* endpoint_cache) const
    {
      const unsigned int size = list.size();
      index = find_with_proto_match(proto_override, index, proto_override_fail, endpoint_cache);
      Item item = list[index % size];
      if (!server_override.empty())
	item.server_host = server_override;
      // OPENVPN_LOG("****** GET REMOTE index=" << index << " so=" << server_override << " po=" << proto_override.str() << " item=" << item.render());
      return item;
    }

    size_t size() const { return list.size(); }
    const Item& operator[](const size_t i) const { return list[i]; }

    std::string render() const
    {
      std::ostringstream out;
      for (size_t i = 0; i < list.size(); ++i)
	{
	  const Item& e = list[i];
	  out << '[' << i << "] " << e.render() << std::endl;
	}
      return out.str();
    }

  private:
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
	    validate_port(default_port);
	  }
      }

      // cycle through remote entries
      {
	const OptionList::IndexList* rem = opt.get_index_ptr("remote");
	if (rem)
	  {
	    for (OptionList::IndexList::const_iterator i = rem->begin(); i != rem->end(); ++i)
	      {
		Item e;
		const Option& o = opt[*i];
		e.server_host = o.get(1, 256);
		if (o.size() >= 3)
		  {
		    e.server_port = o.get(2, 16);
		    validate_port(e.server_port);
		  }
		else
		  e.server_port = default_port;
		if (o.size() >= 4)
		  e.transport_protocol = Protocol::parse(o.get(3, 16), false);
		else
		  e.transport_protocol = default_proto;
		list.push_back(e);
	      }
	  }
      }
    }

    unsigned int find_with_proto_match(const Protocol& proto,
				       const unsigned int index,
				       bool* proto_override_fail,
				       const EndpointCache* ec) const
    {
      const unsigned int size = list.size();
      const unsigned int limit = index + size;
      for (unsigned int i = index; i < limit; ++i)
	{
	  const Item& item = list[i % size];
	  if ((!proto.defined() || proto.transport_match(item.transport_protocol))
	      && (!ec || ec->has_endpoint(item.server_host)))
	    return i;
	}
      if (proto_override_fail)
	*proto_override_fail = true;
      return index;
    }

    void validate_port(const std::string& port)
    {
      if (!parse_number_validate<unsigned int>(port, 5, 1, 65535))
	OPENVPN_THROW(option_error, "bad port number: " << port);
    }

    std::vector<Item> list;
  };

}

#endif
