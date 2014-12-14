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

#ifndef OPENVPN_SERVER_LISTENLIST_H
#define OPENVPN_SERVER_LISTENLIST_H

#include <string>
#include <vector>
#include <utility> // for std::move

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

      std::string addr;
      std::string port;
      Protocol proto;
      unsigned int n_threads;
    };

    struct List : public std::vector<Item>
    {
      List(const OptionList& opt)
      {
	const OptionList::IndexList* listen = opt.get_index_ptr("listen");
	if (listen)
	  {
	    reserve(listen->size());
	    for (OptionList::IndexList::const_iterator i = listen->begin(); i != listen->end(); ++i)
	      {
		const Option& o = opt[*i];
		o.touch();

		Item e;
		e.addr = o.get(1, 128);
		e.port = o.get(2, 16);
		validate_port(e.port, "listen port");
		e.proto = Protocol::parse(o.get(3, 16), false, "listen protocol");
		const IP::Addr addr = IP::Addr(e.addr, "listen addr");
		e.proto.mod_addr_version(addr);
		const std::string n_threads = o.get_default(4, 16, "1");
		if (!parse_number_validate<unsigned int>(n_threads, 3, 1, 100, &e.n_threads))
		  OPENVPN_THROW(option_error, "listen: bad num threads: " << n_threads);
		push_back(std::move(e));
	      }
	  }
	else
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
      }
    };
  }
}

#endif
