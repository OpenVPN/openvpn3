//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Inc.
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

#pragma once

#include <cstdint> // for std::uint32_t, uint64_t, etc.

#include <lz4.h>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/common/socktypes.hpp> // for ntohl/htonl

namespace openvpn {
  inline BufferPtr compress_lz4(const ConstBuffer& src,
				const size_t headroom,
				const size_t tailroom)
  {
    // sanity check
    if (src.size() > LZ4_MAX_INPUT_SIZE)
      return BufferPtr();

    // allocate dest buffer
    BufferPtr dest = new BufferAllocated(sizeof(std::uint32_t) + headroom + tailroom + LZ4_COMPRESSBOUND(src.size()), 0);
    dest->init_headroom(headroom);

    // as a hint to receiver, write the decompressed size
    {
      const std::uint32_t size = htonl(src.size());
      dest->write(&size, sizeof(size));
    }

    // compress
    const int comp_size = ::LZ4_compress_default((const char *)src.c_data(), (char *)dest->data_end(),
					       (int)src.size(), (int)dest->remaining(tailroom));
    if (comp_size <= 0)
      return BufferPtr();
    dest->inc_size(comp_size);
    return dest;
  }

  inline BufferPtr decompress_lz4(const ConstBuffer& source,
				  const size_t headroom,
				  const size_t tailroom,
				  const size_t max_decompressed_size=LZ4_MAX_INPUT_SIZE)
  {
    // get the decompressed size
    ConstBuffer src(source);
    if (src.size() < sizeof(std::uint32_t))
      return BufferPtr();
    std::uint32_t size;
    src.read(&size, sizeof(size));
    size = ntohl(size);
    if (size > max_decompressed_size)
      return BufferPtr();

    // allocate dest buffer
    BufferPtr dest = new BufferAllocated(headroom + tailroom + size, 0);
    dest->init_headroom(headroom);

    // decompress
    const int decomp_size = LZ4_decompress_safe((const char *)src.c_data(), (char *)dest->data(),
						(int)src.size(), size);
    if (decomp_size <= 0 || decomp_size != size)
      return BufferPtr();
    dest->inc_size(decomp_size);
    return dest;
  }
}
