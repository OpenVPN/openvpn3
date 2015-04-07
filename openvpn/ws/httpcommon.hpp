//
//  OpenVPN
//
//  Copyright (C) 2012-2015 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_WS_HTTPCOMMON_H
#define OPENVPN_WS_HTTPCOMMON_H

#include <openvpn/common/number.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/http/header.hpp>

namespace openvpn {
  namespace WS {
    template <typename T>
    inline T get_content_length(const HTTP::HeaderList& headers,
				const T chunked_ret)
    {
      const std::string transfer_encoding = headers.get_value_trim("transfer-encoding");
      if (!string::strcasecmp(transfer_encoding, "chunked"))
	{
	  return chunked_ret;
	}
      else
	{
	  const std::string content_length_str = headers.get_value_trim("content-length");
	  if (content_length_str.empty())
	    return 0;
	  const T content_length = parse_number_throw<T>(content_length_str, "content-length");
	  if (content_length < 0)
	    throw number_parse_exception("content-length is < 0");
	  return content_length;
	}
    }
  }
}

#endif
