#ifndef OPENVPN_COMPRESS_SNAPPY_H
#define OPENVPN_COMPRESS_SNAPPY_H

// Implement Snappy compression.
// Should only be included by compress.hpp

#include <snappy.h>

namespace openvpn {

  class CompressSnappy : public Compress
  {
    // magic number for Snappy compression
    enum {
      SNAPPY_COMPRESS = 0x68,
    };

  public:
    CompressSnappy(const Frame::Ptr& frame, const ProtoStats::Ptr& stats)
      : Compress(frame, stats)
    {
    }

  private:
    virtual void compress(BufferAllocated& buf, const bool hint)
    {
      // skip null packets
      if (!buf.size())
	return;

      if (hint)
	{
	  // initialize work buffer
	  frame->prepare(Frame::COMPRESS_WORK, work);

	  // verify that input data length is not too large
	  if (snappy::MaxCompressedLength(buf.size()) > work.max_size())
	    {
	      error(buf);
	      return;
	    }

	  // do compress
	  size_t comp_size;
	  snappy::RawCompress((const char *)buf.c_data(), buf.size(), (char *)work.data(), &comp_size);

	  // did compression actually reduce data length?
	  if (comp_size < buf.size())
	    {
	      work.set_size(comp_size);
	      do_swap(work, SNAPPY_COMPRESS);
	      buf.swap(work);
	      OPENVPN_LOG_COMPRESS("SNAPPY compress");
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
	case SNAPPY_COMPRESS:
	  {
	    do_unswap(buf);

	    // initialize work buffer
	    const size_t payload_size = frame->prepare(Frame::DECOMPRESS_WORK, work);

	    // do uncompress
	    size_t decomp_size;
	    if (!snappy::GetUncompressedLength((const char *)buf.c_data(), buf.size(), &decomp_size)
		|| decomp_size > payload_size)
	      {
		error(buf);
		break;
	      }
	    if (!snappy::RawUncompress((const char *)buf.c_data(), buf.size(), (char *)work.data()))
	      {
		error(buf);
		break;
	      }
	    work.set_size(decomp_size);
	    buf.swap(work);
	    OPENVPN_LOG_COMPRESS("SNAPPY uncompress");
	  }
	  break;
	default: 
	  error(buf); // unknown op
	}
    }

    BufferAllocated work;
  };

} // namespace openvpn

#endif // OPENVPN_COMPRESS_SNAPPY_H
