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

#ifndef OPENVPN_BUFFER_ZLIB_H
#define OPENVPN_BUFFER_ZLIB_H

#include <cstring> // for std::memset

#include <zlib.h>

#include <openvpn/common/exception.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/frame/frame.hpp>

namespace openvpn {
  namespace ZLib {
    OPENVPN_EXCEPTION(zlib_error);

    inline BufferPtr compress_gzip(BufferPtr src,
				   const size_t headroom,
				   const size_t tailroom,
				   const int level,
				   const int window_bits=15,
				   const int mem_level=8)
    {
      const int GZIP_ENCODING = 16;
      if (src)
	{
	  int status;
	  z_stream zs;

	  std::memset(&zs, 0, sizeof(zs));
	  zs.next_in = src->data();
	  zs.avail_in = src->size();
	  status = ::deflateInit2(&zs,
				  level,
				  Z_DEFLATED,
				  GZIP_ENCODING + window_bits,
				  mem_level,
				  Z_DEFAULT_STRATEGY);
	  if (status != Z_OK)
	    OPENVPN_THROW(zlib_error, "zlib deflateinit2 failed, error=" << status);
	  const uLong outcap = ::deflateBound(&zs, src->size());
	  BufferPtr b = new BufferAllocated(outcap + headroom + tailroom, 0);
	  b->init_headroom(headroom);
	  zs.next_out = b->data();
	  zs.avail_out = outcap;
	  status = ::deflate(&zs, Z_FINISH);
	  if (status != Z_STREAM_END)
	    OPENVPN_THROW(zlib_error, "zlib deflate failed, error=" << status);
	  b->set_size(zs.total_out);
	  ::deflateEnd(&zs);
	  return b;
	}
      else
	return BufferPtr();
    }
  }
}

#endif
