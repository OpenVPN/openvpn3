//
//  frame_init.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Method to generate a Frame object for typical OpenVPN usage

#ifndef OPENVPN_FRAME_FRAME_INIT_H
#define OPENVPN_FRAME_FRAME_INIT_H

#include <openvpn/frame/frame.hpp>

namespace openvpn {

  inline Frame::Ptr frame_init()
  {
    const size_t payload = 2048;
    const size_t control_channel_payload = 1350;
    const size_t headroom = 512;
    const size_t tailroom = 512;
    const size_t align_block = 16;
    const unsigned int buffer_flags = 0;

    Frame::Ptr frame(new Frame(Frame::Context(headroom, payload, tailroom, 0, align_block, buffer_flags)));
    (*frame)[Frame::READ_LINK_TCP] = Frame::Context(headroom, payload, tailroom, 3, align_block, buffer_flags);
    (*frame)[Frame::READ_LINK_UDP] = Frame::Context(headroom, payload, tailroom, 1, align_block, buffer_flags);
    (*frame)[Frame::READ_BIO_MEMQ_STREAM] = Frame::Context(headroom, control_channel_payload, tailroom, 0, align_block, buffer_flags);
    frame->standardize_capacity(~0);
    return frame;
  }

} // namespace openvpn

#endif // OPENVPN_FRAME_FRAME_INIT_H
