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

// General-purpose function for dealing with unicode.

#ifndef OPENVPN_COMMON_UNICODE_H
#define OPENVPN_COMMON_UNICODE_H

#include <string>
#include <algorithm>         // for std::min

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/unicode-impl.hpp>
#include <openvpn/buffer/buffer.hpp>

namespace openvpn {
  namespace Unicode {

    OPENVPN_SIMPLE_EXCEPTION(unicode_src_overflow);
    OPENVPN_SIMPLE_EXCEPTION(unicode_dest_overflow);
    OPENVPN_SIMPLE_EXCEPTION(unicode_malformed);

    // Return true if the given buffer is a valid UTF-8 string
    inline bool is_valid_utf8(const unsigned char *source, size_t size)
    {
      while (size)
	{
	  const unsigned char c = *source;
	  if (c == '\0')
	    return false;
	  const int length = trailingBytesForUTF8[c]+1;
	  if ((size_t)length > size)
	    return false;
	  if (!isLegalUTF8(source, length))
	    return false;
	  source += length;
	  size -= length;
	}
      return true;
    }

    inline bool is_valid_utf8(const std::string& str)
    {
      return is_valid_utf8((const unsigned char *)str.c_str(), str.length());
    }

    // Return the byte position in the string that corresponds with
    // the given character index.  Return values:
    enum {
      UTF8_GOOD=0, // succeeded, result in index
      UTF8_BAD,    // failed, string is not legal UTF8
      UTF8_RANGE,  // failed, index is beyond end of string
    };
    inline int utf8_index(std::string& str, size_t& index)
    {
      const size_t size = str.length();
      size_t upos = 0;
      size_t pos = 0;
      while (pos < size)
	{
	  const int len = trailingBytesForUTF8[(unsigned char)str[pos]]+1;
	  if (pos + len > size || !isLegalUTF8((const unsigned char *)&str[pos], len))
	    return UTF8_BAD;
	  if (upos >= index)
	    {
	      index = pos;
	      return UTF8_GOOD;
	    }
	  pos += len;
	  ++upos;
	}
      return UTF8_RANGE;
    }

    // Truncate a UTF8 string if its length exceeds max_len
    inline void utf8_truncate(std::string& str, size_t max_len)
    {
      const int status = utf8_index(str, max_len);
      if (status == UTF8_GOOD || status == UTF8_BAD)
	str = str.substr(0, max_len);
    }

    // Return a printable UTF-8 string, where bad UTF-8 chars and
    // control chars are mapped to '?'.
    // If max_len_flags > 0, print a maximum of max_len_flags chars.
    // If UTF8_PASS_FMT flag is set in max_len_flags, pass through \r\n\t
    enum {
      UTF8_PASS_FMT=(1<<31),
      UTF8_FILTER=(1<<30),
    };
    inline std::string utf8_printable(const std::string& str, size_t max_len_flags)
    {
      std::string ret;
      const size_t size = str.length();
      const size_t max_len = max_len_flags & ((size_t)UTF8_FILTER-1); // NOTE -- use smallest flag value here
      size_t upos = 0;
      size_t pos = 0;
      ret.reserve(std::min(str.length(), max_len) + 3); // add 3 for "..."
      while (pos < size)
	{
	  if (!max_len || upos < max_len)
	    {
	      unsigned char c = str[pos];
	      int len = trailingBytesForUTF8[c]+1;
	      if (pos + len <= size
		  && c >= 0x20 && c != 0x7F
		  && isLegalUTF8((const unsigned char *)&str[pos], len))
		{
		  // non-control, legal UTF-8
		  ret.append(str, pos, len);
		}
	      else
		{
		  // control char or bad UTF-8 char
		  if (c == '\r' || c == '\n' || c == '\t')
		    {
		      if (!(max_len_flags & UTF8_PASS_FMT))
			c = ' ';
		    }
		  else if (max_len_flags & UTF8_FILTER)
		    c = 0;
		  else
		    c = '?';
		  if (c)
		    ret += c;
		  len = 1;
		}
	      pos += len;
	      ++upos;
	    }
	  else
	    {
	      ret.append("...");
	      break;
	    }
	}
      return ret;
    }

    inline size_t utf8_length(const std::string& str)
    {
      const size_t size = str.length();
      size_t upos = 0;
      size_t pos = 0;
      while (pos < size)
	{
	  int len = trailingBytesForUTF8[(unsigned char)str[pos]]+1;
	  if (!isLegalUTF8((const unsigned char *)&str[pos], len))
	    len = 1;
	  pos += len;
	  ++upos;
	}
      return upos;
    }

    inline void conversion_result_throw(const ConversionResult res)
    {
      switch (res)
	{
	case conversionOK:
	  return;
	case sourceExhausted:
	  throw unicode_src_overflow();
	case targetExhausted:
	  throw unicode_dest_overflow();
	case sourceIllegal:
	  throw unicode_malformed();
	}
    }

    // Convert a UTF-8 std::string to UTF-16 little endian (no null termination in return)
    inline BufferPtr string_to_utf16(const std::string& str)
    {
      ScopedPtr<UTF16, PtrArrayFree> utf16_dest(new UTF16[str.length()]);    
      const UTF8 *src = (UTF8 *)str.c_str();
      UTF16 *dest = utf16_dest.get();
      const ConversionResult res = ConvertUTF8toUTF16(&src, src + str.length(),
						      &dest, dest + str.length(),
						      lenientConversion);
      conversion_result_throw(res);
      BufferPtr ret(new BufferAllocated((dest - utf16_dest.get()) * 2, BufferAllocated::ARRAY));
      UTF8 *d = ret->data();
      for (const UTF16 *s = utf16_dest.get(); s < dest; ++s)
	{
	  *d++ = *s & 0xFF;
	  *d++ = (*s >> 8) & 0xFF;
	}
      return ret;
    }
  }
}

#endif
