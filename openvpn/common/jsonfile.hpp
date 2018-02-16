//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.

#pragma once

#include <openvpn/common/jsonhelper.hpp>
#include <openvpn/common/fileatomic.hpp>

namespace openvpn {
  namespace json {

    inline Json::Value read_fast(const std::string& fn)
    {
      BufferPtr bp = read_binary_unix(fn, 0, NULL_ON_ENOENT);
      if (!bp || bp->empty())
	return Json::Value();
      return parse_from_buffer(*bp, fn);
    }

    inline void write_atomic(const std::string& fn,
			     const std::string& tmpdir,
			     const mode_t mode,
			     const Json::Value& root,
			     const size_t size_hint,
			     RandomAPI& rng)
    {
      BufferPtr bp = new BufferAllocated(size_hint, BufferAllocated::GROW);
      write_binary_atomic(fn, tmpdir, mode, *bp, rng);
    }
  }
}
