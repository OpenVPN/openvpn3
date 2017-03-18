// OpenVPN
// Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
// All rights reserved

#ifndef OPENVPN_SSL_IS_OPENVPN_PROTOCOL_H
#define OPENVPN_SSL_IS_OPENVPN_PROTOCOL_H

#include <algorithm>                // for std::min

#include <openvpn/common/size.hpp>  // for size_t

namespace openvpn {

  // Peek at the first few bytes of a session and
  // distinguishing between OpenVPN or SSL protocols.
  inline bool is_openvpn_protocol(const unsigned char *p, const size_t len)
  {
    const int CONTROL_HARD_RESET_CLIENT_V2 = 7;
    const int OPCODE_SHIFT = 3;
    const int MIN_INITIAL_PKT_SIZE = 14;

    switch (std::min(len, size_t(3)))
      {
      case 3:
	return p[0] == 0
	  && p[1] >= MIN_INITIAL_PKT_SIZE
	  && p[2] == (CONTROL_HARD_RESET_CLIENT_V2 << OPCODE_SHIFT);
      case 2:
	return p[0] == 0 && p[1] >= MIN_INITIAL_PKT_SIZE;
      case 1:
	return p[0] == 0;
      default:
	return true;
      }
  }

}
#endif
