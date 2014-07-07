//
//  base64.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// General-purpose base64 encode and decode.

#ifndef OPENVPN_COMMON_BASE64_H
#define OPENVPN_COMMON_BASE64_H

#include <string>
#include <cstring> // for std::memset, std::strlen

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {

  class Base64 {
  public:
    OPENVPN_SIMPLE_EXCEPTION(base64_bad_map);
    OPENVPN_SIMPLE_EXCEPTION(base64_decode_error);

    // altmap is "+/=" by default
    Base64(const char *altmap = NULL)
    {
      // build encoding map
      {
	unsigned int i;
	unsigned int j = 65;
	for (i = 0; i < 62; ++i)
	  {
	    enc[i] = j++;
	    if (j == 91)
	      j = 97;
	    else if (j == 123)
	      j = 48;
	  }
	if (!altmap)
	  altmap = "+/=";
	enc[62] = altmap[0];
	enc[63] = altmap[1];
	equal = altmap[2];
      }

      // build decoding map
      {
	std::memset(dec, 0xFF, 128);
	for (unsigned int i = 0; i < 64; ++i)
	  {
	    const unsigned char c = enc[i];
	    if (c >= 128)
	      throw base64_bad_map();
	    dec[c] = i;
	  }
      }
    }

    static size_t decode_size_max(const size_t encode_size)
    {
      return encode_size;
    }

    static size_t encode_size_max(const size_t decode_size)
    {
      return decode_size * 4 / 3 + 4;
    }

    template <typename V>
    std::string encode(const V& data) const
    {
      char *s, *p;
      size_t i;
      unsigned int c;
      const size_t size = data.size();

      p = s = new char[encode_size_max(size)];
      for (i = 0; i < size; ) {
	c = data[i++] << 8;
	if (i < size)
	  c += data[i];
	i++;
	c <<= 8;
	if (i < size)
	  c += data[i];
	i++;
	p[0] = enc[(c & 0x00fc0000) >> 18];
	p[1] = enc[(c & 0x0003f000) >> 12];
	p[2] = enc[(c & 0x00000fc0) >> 6];
	p[3] = enc[c & 0x0000003f];
	if (i > size)
	  p[3] = equal;
	if (i > size + 1)
	  p[2] = equal;
	p += 4;
      }
      *p = '\0';
      const std::string ret(s);
      delete [] s;
      return ret;
    }

    std::string decode(const std::string& str) const
    {
      std::string ret;
      ret.reserve(str.length());
      decode(ret, str);
      return ret;
    }

    template <typename V>
    void decode(V& dest, const std::string& str) const
    {
      for (const char *p = str.c_str(); *p != '\0' && (*p == equal || is_base64_char(*p)); p += 4)
	{
	  unsigned int marker;
	  const unsigned int val = token_decode(p, marker);
	  dest.push_back((val >> 16) & 0xff);
	  if (marker < 2)
	    dest.push_back((val >> 8) & 0xff);
	  if (marker < 1)
	    dest.push_back(val & 0xff);
	}
    }

  private:
    bool is_base64_char(const char c) const
    {
      const size_t idx = c;
      return idx < 128 && dec[idx] != 0xFF;
    }

    unsigned int decode_base64_char(const char c) const
    {
      const size_t idx = c;
      if (idx >= 128)
	throw base64_decode_error();
      const unsigned int v = dec[idx];
      if (v == 0xFF)
	throw base64_decode_error();
      return v;
    }

    unsigned int token_decode(const char *token, unsigned int& marker) const
    {
      size_t i;
      unsigned int val = 0;
      marker = 0; // number of equal chars seen
      if (std::strlen(token) < 4)
	throw base64_decode_error();
      for (i = 0; i < 4; i++)
	{
	  val <<= 6;
	  if (token[i] == equal)
	    marker++;
	  else if (marker > 0)
	    throw base64_decode_error();
	  else
	    val += decode_base64_char(token[i]);
	}
      if (marker > 2)
	throw base64_decode_error();
      return val;
    }

    unsigned char enc[64];
    unsigned char dec[128];
    unsigned char equal;
  };

  // provide a static Base64 object

  const Base64* base64; // GLOBAL

  inline void base64_init_static()
  {
    if (!base64)
      base64 = new Base64();
  }

  inline void base64_uninit_static()
  {
    if (base64)
      {
	delete base64;
	base64 = NULL;
      }
  }

}

#endif
