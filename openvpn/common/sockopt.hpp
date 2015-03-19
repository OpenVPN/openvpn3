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

#ifndef OPENVPN_COMMON_SOCKOPT_H
#define OPENVPN_COMMON_SOCKOPT_H

#include <sys/types.h>
#include <sys/socket.h>

#include <openvpn/common/exception.hpp>

namespace openvpn {
  namespace SockOpt {

    // set SO_REUSEPORT for inter-thread load balancing
    inline void reuseport(const int fd)
    {
      int on = 1;
      if (::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
		     (void *)&on, sizeof(on)) < 0)
	throw Exception("error setting SO_REUSEPORT on socket");
    }

    // set SO_REUSEADDR for TCP
    inline void reuseaddr(const int fd)
    {
      int on = 1;
      if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		     (void *)&on, sizeof(on)) < 0)
	throw Exception("error setting SO_REUSEADDR on socket");
    }

    // set TCP_NODELAY for TCP
    inline void tcp_nodelay(const int fd)
    {
      int state = 1;
      if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
		     (void *)&state, sizeof(state)) != 0)
	throw Exception("error setting TCP_NODELAY on socket");
    }
  }
}

#endif
