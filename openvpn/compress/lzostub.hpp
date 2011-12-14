#ifndef OPENVPN_COMPRESS_LZOSTUB_H
#define OPENVPN_COMPRESS_LZOSTUB_H

namespace openvpn {

  class CompressLZOStub : public Compress
  {
    // magic numbers to tell our peer if we compressed or not
    enum {
      YES_COMPRESS = 0x66,
      NO_COMPRESS = 0xFA,
    };

  public:
    CompressLZOStub(const Frame::Ptr& frame, const ProtoStats::Ptr& stats)
      : Compress(frame, stats)
    {
    }

  private:
    virtual void compress(BufferAllocated& buf)
    {
      // skip null packets
      if (!buf.size())
	return;

      // indicate that we didn't compress
      buf.push_front(NO_COMPRESS);
    }

    virtual void decompress(BufferAllocated& buf)
    {
      // skip null packets
      if (!buf.size())
	return;

      const unsigned char c = buf.pop_front();
      if (c == NO_COMPRESS) // what we're expecting
	return;

      // error
      stats->error(ProtoStats::COMPRESS_ERRORS);
      buf.reset_size();
    }
  };

} // namespace openvpn

#endif // OPENVPN_COMPRESS_LZOSTUB_H
