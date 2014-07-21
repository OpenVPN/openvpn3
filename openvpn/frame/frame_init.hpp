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
