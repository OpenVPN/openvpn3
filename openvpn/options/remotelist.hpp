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
    };

    RemoteList(const OptionList& opt)
    {
      const OptionList::IndexList& rem = opt.get_index("remote");
      for (OptionList::IndexList::const_iterator i = rem.begin(); i != rem.end(); i++)
	{
	  Item e;
	  const Option& o = opt[*i];
	  e.server_host = o.get(1);
	  e.server_port = o.get(2);
	  e.transport_protocol = Protocol::parse(o.get(3));
	  list.push_back(e);
	}
    }

    // used to cycle through Item list
    const Item& modulo_ref(const size_t i) { return list[i % list.size()]; } 

    size_t size() const { return list.size(); }
    const Item& operator[](const size_t i) { return list[i]; }

#ifdef OPENVPN_DEBUG
    std::string debug_render() const
    {
      std::ostringstream out;
      for (size_t i = 0; i < list.size(); ++i)
	{
	  const Item& e = list[i];
	  out << '[' << i
	      << "] host=" << e.server_host
	      << " port=" << e.server_port
	      << " proto=" << e.transport_protocol.str()
	      << std::endl;
	}
      return out.str();
    }
#endif

  private:
    std::vector<Item> list;
  };

}

#endif
