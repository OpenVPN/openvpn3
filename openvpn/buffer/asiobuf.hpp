//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

#ifndef OPENVPN_BUFFER_ASIOBUF_H
#define OPENVPN_BUFFER_ASIOBUF_H

#include <asio.hpp>

#include <openvpn/buffer/buffer.hpp>

namespace openvpn {
  class AsioConstBufferSeq2
  {
  public:
    AsioConstBufferSeq2(const Buffer& b1, const Buffer& b2)
      : buf({{b1.c_data(), b1.size()},
	     {b2.c_data(), b2.size()}})
    {
    }

    // Implement the ConstBufferSequence requirements.
    typedef asio::const_buffer value_type;
    typedef const asio::const_buffer* const_iterator;
    const asio::const_buffer* begin() const { return buf; }
    const asio::const_buffer* end() const { return buf + 2; }

    const size_t size() const
    {
      return asio::buffer_size(buf[0])
	   + asio::buffer_size(buf[1]);
    }

  private:
    const asio::const_buffer buf[2];
  };
}

#endif
