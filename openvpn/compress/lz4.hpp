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

#ifndef OPENVPN_COMPRESS_LZ4_H
#define OPENVPN_COMPRESS_LZ4_H

// Implement LZ4 compression.
// Should only be included by compress.hpp

#include <algorithm> // for std::max

#include <lz4.h>

namespace openvpn {

  class CompressLZ4 : public Compress
  {
    // magic number for LZ4 compression
    enum {
      LZ4_COMPRESS = 0x69,
    };

  public:
    CompressLZ4(const Frame::Ptr& frame, const SessionStats::Ptr& stats, const bool asym_arg)
      : Compress(frame, stats),
	asym(asym_arg)
    {
      OPENVPN_LOG_COMPRESS("LZ4 init asym=" << asym_arg);
    }

    virtual const char *name() const { return "lz4"; }

    virtual void compress(BufferAllocated& buf, const bool hint)
    {
      // skip null packets
      if (!buf.size())
	return;

      if (hint && !asym)
	{
	  // initialize work buffer
	  frame->prepare(Frame::COMPRESS_WORK, work);

	  // verify that input data length is not too large
	  if (lz4_extra_buffer(buf.size()) > work.max_size())
	    {
	      error(buf);
	      return;
	    }

	  // do compress
	  const int comp_size = LZ4_compress((const char *)buf.c_data(), (char *)work.data(), (int)buf.size());

	  // did compression actually reduce data length?
	  if (comp_size < buf.size())
	    {
	      if (comp_size < 0)
		{
		  error(buf);
		  return;
		}
	      OPENVPN_LOG_COMPRESS_VERBOSE("LZ4 compress " << buf.size() << " -> " << comp_size);
	      work.set_size(comp_size);
	      do_swap(work, LZ4_COMPRESS);
	      buf.swap(work);
	      return;
	    }
	}

      // indicate that we didn't compress
      do_swap(buf, NO_COMPRESS_SWAP);
    }

    virtual void decompress(BufferAllocated& buf)
    {
      // skip null packets
      if (!buf.size())
	return;

      const unsigned char c = buf.pop_front();
      switch (c)
	{
	case NO_COMPRESS_SWAP:
	  do_unswap(buf);
	  break;
	case LZ4_COMPRESS:
	  {
	    do_unswap(buf);

	    // initialize work buffer
	    const int payload_size = frame->prepare(Frame::DECOMPRESS_WORK, work);

	    // do uncompress
	    const int decomp_size = LZ4_decompress_safe((const char *)buf.c_data(), (char *)work.data(), (int)buf.size(), payload_size);
	    if (decomp_size < 0)
		{
		  error(buf);
		  return;
		}
	    OPENVPN_LOG_COMPRESS_VERBOSE("LZ4 uncompress " << buf.size() << " -> " << decomp_size);
	    work.set_size(decomp_size);
	    buf.swap(work);
	  }
	  break;
	default: 
	  error(buf); // unknown op
	}
    }

  private:
    // Worst case size expansion on compress.
    // Official LZ4 worst-case size expansion alg is
    // LZ4_COMPRESSBOUND macro in lz4.h.
    // However we optimize it slightly here to lose the integer division
    // when len < 65535.
    size_t lz4_extra_buffer(const size_t len)
    {
      if (likely(len < 65535))
	return len + len/256 + 17;
      else
	return len + len/255 + 16;
    }

    const bool asym;
    BufferAllocated work;
  };

} // namespace openvpn

#endif // OPENVPN_COMPRESS_LZ4_H
