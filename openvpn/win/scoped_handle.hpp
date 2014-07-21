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

      HANDLE* ref()
      {
	return &handle;
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
