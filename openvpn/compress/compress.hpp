#ifndef OPENVPN_COMPRESS_COMPRESS_H
#define OPENVPN_COMPRESS_COMPRESS_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/log/protostats.hpp>

namespace openvpn {
  class Compress : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<Compress> Ptr;

    // Compression method implemented by underlying compression class
    // hint should normally be true to compress the data.  If hint is
    // false, the data may be uncompressible or already compressed.
    virtual void compress(BufferAllocated& buf, const bool hint) = 0;

    // Decompression method implemented by underlying compression class.
    virtual void decompress(BufferAllocated& buf) = 0;

  protected:
    Compress(const Frame::Ptr& frame_arg,
	     const ProtoStats::Ptr& stats_arg)
      : frame(frame_arg), stats(stats_arg) {}

    Frame::Ptr frame;
    ProtoStats::Ptr stats;
  };
}// namespace openvpn

// include compressor implementations here
#include <openvpn/compress/lzostub.hpp>

namespace openvpn {
  class CompressContext
  {
  public:
    enum Type {
      NONE,
      LZO_STUB,
      LZO,
    };

    OPENVPN_SIMPLE_EXCEPTION(compress_instantiate);

    CompressContext() : type_(NONE) {}
    CompressContext(const Type t) : type_(t) {}

    unsigned int extra_payload_bytes() const { return 1; }

    Compress::Ptr new_compressor(const Frame::Ptr& frame, const ProtoStats::Ptr& stats)
    {
      switch (type_)
	{
	case LZO_STUB:
	  return new CompressLZOStub(frame, stats);
	default:
	  throw compress_instantiate();
	}
    }

    const char *peer_info_string() const
    {
      switch (type_)
	{
	case LZO:
	  return NULL;
	case LZO_STUB:
	  return "IV_LZO_STUB=1\n";
	default:
	  return NULL;
	}
    }

    const char *options_string() const
    {
      switch (type_)
	{
	case LZO:
	case LZO_STUB:
	  return "comp-lzo";
	default:
	  return NULL;
	}
    }

    const char *str() const
    {
      switch (type_)
	{
	case LZO:
	  return "LZO";
	case LZO_STUB:
	  return "LZO_STUB";
	default:
	  return "NONE";
	}
    }

  private:
    Type type_;
  };

} // namespace openvpn

#endif // OPENVPN_COMPRESS_COMPRESS_H
