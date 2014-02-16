//
//  scoped_handle.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// scoped HANDLE for windows

#ifndef OPENVPN_WIN_SCOPED_HANDLE_H
#define OPENVPN_WIN_SCOPED_HANDLE_H

#include <windows.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/win/handle.hpp>

namespace openvpn {
  namespace Win {
    class ScopedHANDLE : boost::noncopyable
    {
    public:
      typedef HANDLE base_type;

      ScopedHANDLE() : handle(Handle::undefined()) {}

      explicit ScopedHANDLE(HANDLE h)
	: handle(h) {}

      HANDLE release()
      {
	const HANDLE ret = handle;
	handle = NULL;
	return ret;
      }

      bool defined() const
      {
	return Handle::defined(handle);
      }

      HANDLE operator()() const
      {
	return handle;
      }

      void reset(HANDLE h)
      {
	close();
	handle = h;
      }

      // unusual semantics: replace handle without closing it first
      void replace(HANDLE h)
      {
	handle = h;
      }

      bool close()
      {
	if (defined())
	  {
	    const BOOL ret = CloseHandle(handle);
	    //OPENVPN_LOG("**** SH CLOSE hand=" << handle << " ret=" << ret);
	    handle = NULL;
	    return ret != 0;
	  }
	else
	  return true;
      }

      ~ScopedHANDLE()
      {
	close();
      }

    private:
      HANDLE handle;
    };

  }
}

#endif
