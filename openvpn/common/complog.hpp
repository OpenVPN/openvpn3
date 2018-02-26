//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.

#pragma once

namespace openvpn {
  inline void log_compress(const std::string prefix, const size_t orig_size, const size_t new_size)
  {
    OPENVPN_LOG(prefix
		<< ' ' << orig_size
		<< " -> " << new_size
		<< " -- compression ratio: " << double(orig_size) / double(new_size));
  }
}
