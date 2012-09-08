//
//  lzoselect.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMPRESS_LZOSELECT_H
#define OPENVPN_COMPRESS_LZOSELECT_H

#if defined(HAVE_LZO)
#include <openvpn/compress/lzo.hpp>
#else
#include <openvpn/compress/lzoasym.hpp>
#endif

namespace openvpn {
#if !defined(HAVE_LZO)
  typedef CompressLZOAsym CompressLZO;
#endif
}

#endif
