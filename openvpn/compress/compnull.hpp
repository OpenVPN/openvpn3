//
//  compnull.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// A null compression class.

#ifndef OPENVPN_COMPRESS_COMPNULL_H
#define OPENVPN_COMPRESS_COMPNULL_H

namespace openvpn {

  class CompressNull : public Compress
  {
  public:
    CompressNull(const Frame::Ptr& frame, const SessionStats::Ptr& stats)
      : Compress(frame, stats)
    {
    }

    virtual const char *name() const { return "null"; }
    virtual void compress(BufferAllocated& buf, const bool hint) {}
    virtual void decompress(BufferAllocated& buf) {}
  };

} // namespace openvpn

#endif // OPENVPN_COMPRESS_COMPNULL_H
