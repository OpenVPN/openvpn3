#ifndef OPENVPN_COMPRESS_COMPNULL_H
#define OPENVPN_COMPRESS_COMPNULL_H

namespace openvpn {

  class CompressNull : public Compress
  {
  public:
    CompressNull(const Frame::Ptr& frame, const ProtoStats::Ptr& stats)
      : Compress(frame, stats)
    {
    }

  private:
    virtual void compress(BufferAllocated& buf, const bool hint) {}
    virtual void decompress(BufferAllocated& buf) {}
  };

} // namespace openvpn

#endif // OPENVPN_COMPRESS_COMPNULL_H
