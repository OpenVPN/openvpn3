//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.

#pragma once

#include <openvpn/common/jsonhelper.hpp>
#include <openvpn/common/fileatomic.hpp>

namespace openvpn {
  namespace json {

    inline Json::Value read_fast(const std::string& fn, const bool optional=true)
    {
      BufferPtr bp = read_binary_unix(fn, 0, optional ? NULL_ON_ENOENT : 0);
      if (!bp || bp->empty())
	return Json::Value();
      return parse_from_buffer(*bp, fn);
    }

    inline void write_atomic(const std::string& fn,
			     const std::string& tmpdir,
			     const mode_t mode,
			     const std::uint64_t mtime_ns,  // set explicit modification-time in nanoseconds since epoch, or 0 to defer to system
			     const Json::Value& root,
			     const size_t size_hint,
			     RandomAPI& rng)
    {
      BufferPtr bp = new BufferAllocated(size_hint, BufferAllocated::GROW);
      format_compact(root, *bp);
      write_binary_atomic(fn, tmpdir, mode, mtime_ns, *bp, rng);
    }

    inline void write_fast(const std::string& fn,
			   const mode_t mode,
			   const std::uint64_t mtime_ns,  // set explicit modification-time in nanoseconds since epoch, or 0 to defer to system
			   const Json::Value& root,
			   const size_t size_hint)
    {
      BufferPtr bp = new BufferAllocated(size_hint, BufferAllocated::GROW);
      format_compact(root, *bp);
      write_binary_unix(fn, mode, mtime_ns, *bp);
    }
  }
}
