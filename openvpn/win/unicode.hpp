//
//  unicode.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_WIN_UNICODE_H
#define OPENVPN_WIN_UNICODE_H

#include <string>

#include <windows.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/scoped_ptr.hpp>

namespace openvpn {
  namespace Win {
    typedef ScopedPtr<wchar_t, PtrArrayFree> UTF16;

    OPENVPN_SIMPLE_EXCEPTION(win_utf16);

    inline wchar_t* utf16(const std::string& str)
    {
      // first get output length (return value includes space for trailing nul)
      const int len = MultiByteToWideChar(CP_UTF8,
					  0,
					  str.c_str(),
					  -1,
					  NULL,
					  0);
      if (len <= 0)
	throw win_utf16();
      UTF16 ret(new wchar_t[len]);
      const int len2 = MultiByteToWideChar(CP_UTF8,
					   0,
					   str.c_str(),
					   -1,
					   ret(),
					   len);
      if (len != len2)
	throw win_utf16();
      return ret.release();
    }

    inline size_t utf16_strlen(const wchar_t *str)
    {
      return wcslen(str);
    }
  }
}
#endif
