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

#ifndef OPENVPN_BUFFER_BUFLIST_H
#define OPENVPN_BUFFER_BUFLIST_H

#include <list>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/buffer/bufstr.hpp>

namespace openvpn {

  struct BufferList : public std::list<BufferPtr>
  {
    BufferPtr join(const size_t headroom,
		   const size_t tailroom,
		   const bool size_1_optim) const
    {
      // special optimization if list contains
      // a single element that satisfies our
      // headroom/tailroom constraints.
      if (size_1_optim
	  && size() == 1
	  && front()->offset() >= headroom
	  && front()->remaining() >= tailroom)
	return front();

      // first pass -- measure total size
      const size_t size = join_size();

      // allocate buffer
      BufferPtr big = new BufferAllocated(size + headroom + tailroom, 0);
      big->init_headroom(headroom);

      // second pass -- copy data
      for (auto &b : *this)
	big->write(b->c_data(), b->size());

      return big;
    }

    BufferPtr join() const
    {
      return join(0, 0, true);
    }

    size_t join_size() const
    {
      size_t size = 0;
      for (auto &b : *this)
	size += b->size();
      return size;
    }

    std::string to_string() const
    {
      BufferPtr bp = join();
      return buf_to_string(*bp);
    }

    BufferList copy() const
    {
      BufferList ret;
      for (auto &b : *this)
	ret.emplace_back(new BufferAllocated(*b));
      return ret;
    }
  };

}

#endif
