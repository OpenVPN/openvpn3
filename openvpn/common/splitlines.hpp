//
//  splitlines.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_SPLITLINES_H
#define OPENVPN_COMMON_SPLITLINES_H

#include <openvpn/common/string.hpp>

namespace openvpn {
  class SplitLines
  {
  public:
    // Note: str passed to constructor is not locally stored, so it must remain in
    // scope and not be modified during the lifetime of the SplitLines object.
    SplitLines(const std::string& str, const size_t max_line_len_arg)
      : data(str.c_str()),
	size(str.length()),
	max_line_len(max_line_len_arg),
	index(0),
	overflow(false) {}

    bool operator()(const bool trim)
    {
      line.clear();
      overflow = false;
      const size_t overflow_index = index + max_line_len;
      while (index < size)
	{
	  if (max_line_len && index >= overflow_index)
	    {
	      overflow = true;
	      return true;
	    }
	  const char c = data[index++];
	  line += c;
	  if (c == '\n' || index >= size)
	    {
	      if (trim)
		string::trim_crlf(line);
	      return true;
	    }
	}
      return false;
    }

    bool line_overflow() const
    {
      return overflow;
    }

    std::string& line_ref()
    {
      return line;
    }

  private:
    const char *data;
    size_t size;
    size_t max_line_len;
    size_t index;
    std::string line;
    bool overflow;
  };
}

#endif
