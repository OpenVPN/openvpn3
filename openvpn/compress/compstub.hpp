//
//  compstub.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMPRESS_COMPSTUB_H
#define OPENVPN_COMPRESS_COMPSTUB_H

#ifdef HAVE_LZO
#include <openvpn/compress/lzo.hpp>
#endif

namespace openvpn {

  class CompressStub : public Compress
  {
  public:
    CompressStub(const Frame::Ptr& frame, const SessionStats::Ptr& stats, const bool support_swap_arg)
      : Compress(frame, stats),
	support_swap(support_swap_arg)
#ifdef HAVE_LZO
        ,lzo(frame, stats, false)
#endif
    {
    }

  private:
    virtual void compress(BufferAllocated& buf, const bool hint)
    {
      // skip null packets
      if (!buf.size())
	return;

      // indicate that we didn't compress
      if (support_swap)
	do_swap(buf, NO_COMPRESS_SWAP);
      else
	buf.push_front(NO_COMPRESS);
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
	case NO_COMPRESS:
	  break;
#ifdef HAVE_LZO
	// special mode to support older servers that ignore
	// compression handshake -- this will handle receiving
	// compressed packets even if we didn't ask for them
	case CompressLZO::LZO_COMPRESS:
	  OPENVPN_LOG_COMPRESS("CompressStub: handled unsolicited LZO packet");
	  lzo.decompress_work(buf);
	  break;
#endif
	default: 
	  OPENVPN_LOG_COMPRESS("CompressStub: unable to handle op=" << int(c));
	  error(buf);
	}
    }

    const bool support_swap;

#ifdef HAVE_LZO
    CompressLZO lzo;
#endif
  };

} // namespace openvpn

#endif // OPENVPN_COMPRESS_COMPSTUB_H
