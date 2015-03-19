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

#ifndef OPENVPN_SERVER_LISTENLIST_H
#define OPENVPN_SERVER_LISTENLIST_H

#include <string>
#include <vector>
#include <utility> // for std::move

#include <boost/algorithm/string.hpp> // for boost::algorithm::starts_with, ends_with

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/port.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/addr/ip.hpp>
#include <openvpn/transport/protocol.hpp>

namespace openvpn {
  namespace Listen {
    struct Item
    {
      Item() : n_threads(0) {}

      std::string directive;
      std::string addr;
      std::string port;
      Protocol proto;
      unsigned int n_threads;

      std::string to_string() const
      {
	std::ostringstream os;
	os << directive << '/' << addr << '/' << port << '/' << proto.str() << '/' << n_threads;
	return os.str();
      }
    };

    class List : public std::vector<Item>
    {
    public:
      List(const OptionList& opt,
	   const std::string& directive,
	   const bool allow_default,
	   const unsigned int n_cores)
      {
	size_t n_listen = 0;

	for (OptionList::const_iterator i = opt.begin(); i != opt.end(); ++i)
	  {
	    const Option& o = *i;
	    if (match(directive, o))
	      ++n_listen;
	  }

	if (n_listen)
	  {
	    reserve(n_listen);

	    for (OptionList::const_iterator i = opt.begin(); i != opt.end(); ++i)
	      {
		const Option& o = *i;
		if (match(directive, o))
		  {
		    o.touch();

		    unsigned int mult = 1;

		    Item e;
		    e.directive = o.get(0, 64);
		    e.addr = o.get(1, 128);
		    e.port = o.get(2, 16);
		    validate_port(e.port, e.directive + " port");
		    {
		      const std::string title = e.directive + " protocol";
		      e.proto = Protocol::parse(o.get(3, 16), false, title.c_str());
		    }
		    {
		      const std::string title = e.directive + " addr";
		      const IP::Addr addr = IP::Addr(e.addr, title.c_str());
		      e.proto.mod_addr_version(addr);
		    }
		    std::string n_threads = o.get_default(4, 16, "1");
		    if (boost::algorithm::ends_with(n_threads, "*N"))
		      {
			mult = n_cores;
			n_threads = n_threads.substr(0, n_threads.length() - 2);
		      }
		    if (!parse_number_validate<unsigned int>(n_threads, 3, 1, 100, &e.n_threads))
		      OPENVPN_THROW(option_error, e.directive << ": bad num threads: " << n_threads);
		    e.n_threads *= mult;
		    push_back(std::move(e));
		  }
	      }
	  }
	else if (allow_default)
	  {
	    Item e;

	    // parse "proto" option if present
	    {
	      const Option* o = opt.get_ptr("proto");
	      if (o)
		e.proto = Protocol::parse(o->get(1, 16), true);
	      else
		e.proto = Protocol(Protocol::UDPv4);
	    }

	    // parse "port" option if present
	    {
	      const Option* o = opt.get_ptr("lport");
	      if (!o)
		o = opt.get_ptr("port");
	      if (o)
		{
		  e.port = o->get(1, 16);
		  validate_port(e.port, "port");
		}
	      else
		e.port = "1194";
	    }

	    // parse "local" option if present
	    {
	      const Option* o = opt.get_ptr("local");
	      if (o)
		{
		  e.addr = o->get(1, 128);
		  const IP::Addr addr = IP::Addr(e.addr, "local addr");
		  e.proto.mod_addr_version(addr);
		}
	      else if (e.proto.is_ipv6())
		e.addr = "::0";
	      else
		e.addr = "0.0.0.0";
	    }

	    // n_threads defaults to one unless "listen" directive is used
	    e.n_threads = 1;

	    push_back(std::move(e));
	  }
	else
	  OPENVPN_THROW(option_error, "no " << directive << " directives found");
      }

      unsigned int total_threads() const
      {
	unsigned int ret = 0;
	for (const_iterator i = begin(); i != end(); ++i)
	  ret += i->n_threads;
	return ret;
      }

    private:
      static bool match(const std::string& directive, const Option& o)
      {
	const size_t len = directive.length();
	if (len && o.size())
	  {
	    if (directive[len-1] == '-')
	      return boost::algorithm::starts_with(o.ref(0), directive);
	    else
	      return o.ref(0) == directive;
	  }
	else
	  return false;
      }
    };
  }
}

#endif
