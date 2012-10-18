//
//  remotelist.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_OPTIONS_REMOTELIST_H
#define OPENVPN_OPTIONS_REMOTELIST_H

#include <string>
#include <sstream>
#include <vector>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/transport/protocol.hpp>

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
      Protocol default_proto(Protocol::UDPv4);
      std::string default_port = "1194";

      // parse "proto" option if present
      {
	const Option* o = opt.get_ptr("proto");
	if (o)
	  default_proto = Protocol::parse(o->get(1));
      }

      // parse "port" option if present
      // fixme -- validate port
      {
	const Option* o = opt.get_ptr("port");
	if (o)
	  default_port = o->get(1);
      }

      // cycle through remote entries
      {
	const OptionList::IndexList& rem = opt.get_index("remote");
	for (OptionList::IndexList::const_iterator i = rem.begin(); i != rem.end(); ++i)
	  {
	    Item e;
	    const Option& o = opt[*i];
	    e.server_host = o.get(1);
	    if (o.size() >= 3)
	      e.server_port = o.get(2);
	    else
	      e.server_port = default_port;
	    if (o.size() >= 4)
	      e.transport_protocol = Protocol::parse(o.get(3));
	    else
	      e.transport_protocol = default_proto;
	    list.push_back(e);
	  }
      }
    }

    // used to cycle through Item list
    Item get(unsigned int& index, const std::string& server_override, const Protocol& proto_override) const
    {
      const unsigned int size = list.size();
      index = find_with_proto_match(proto_override, index);
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
    unsigned int find_with_proto_match(const Protocol& proto, const unsigned int index) const
    {
      if (proto.defined())
	{
	  const unsigned int size = list.size();
	  const unsigned int limit = index + size;
	  for (unsigned int i = index; i < limit; ++i)
	    {
	      const Item& item = list[i % size];
	      if (proto.transport_match(item.transport_protocol))
		return i;
	    }
	}
      return index;
    }

    std::vector<Item> list;
  };

}

#endif
