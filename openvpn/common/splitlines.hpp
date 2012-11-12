//
//  splitlines.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_SPLITLINES_H
#define OPENVPN_COMMON_SPLITLINES_H

namespace openvpn {
  class SplitLines
  {
  public:
    SplitLines(const std::string& str, const size_t max_line_len_arg)
      : data(str.c_str()),
	size(str.length()),
	max_line_len(max_line_len_arg),
	index(0),
	overflow(false) {}

    bool operator()()
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
	  if (c == '\n')
	    return true;
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
