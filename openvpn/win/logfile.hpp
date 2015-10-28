//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_WIN_LOGFILE_H
#define OPENVPN_WIN_LOGFILE_H

#include <windows.h>

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/wstring.hpp>
#include <openvpn/log/logbase.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/win/winerr.hpp>
#include <openvpn/win/secattr.hpp>
#include <openvpn/win/scoped_handle.hpp>

namespace openvpn {
  namespace Win {

    class LogFile : public LogBase
    {
    public:
      typedef RCPtr<LogFile> Ptr;

      LogFile(const std::string& fn,
	      const std::string& sddl_string,
	      bool append)
	: log_handle(create_file(fn, sddl_string, append)),
	  log_context(this)
      {
      }

      virtual void log(const std::string& str) override
      {
	DWORD n_written;
	const std::string line = date_time() + ' ' + str;
	::WriteFile(log_handle(), line.c_str(), line.length(), &n_written, NULL);
      }

    private:
      static ScopedHANDLE create_file(const std::string& fn,
				      const std::string& sddl_string,
				      bool append)
      {
	SecurityAttributes sa(sddl_string, true, "redirect_stdout_stderr");
	const std::wstring wfn = wstring::from_utf8(fn);
	ScopedHANDLE file(::CreateFileW(
	    wfn.c_str(),
	    GENERIC_WRITE,
	    FILE_SHARE_READ,
	    &sa.sa,
	    append ? OPEN_ALWAYS : CREATE_ALWAYS,
	    FILE_ATTRIBUTE_NORMAL,
	    NULL));
	if (!file.defined())
	  {
	    const Win::LastError err;
	    OPENVPN_THROW_EXCEPTION("Win::LogFile: failed to open " << fn << " : " << err.message());
	  }

	// append to logfile?
	if (append)
	  {
	    if (::SetFilePointer(file(), 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
	      {
		const Win::LastError err;
		OPENVPN_THROW_EXCEPTION("Win::LogFile: cannot append to " << fn << " : " << err.message());
	      }
	  }
	return file;
      }

      ScopedHANDLE log_handle;
      Log::Context log_context; // must be initialized last
    };

  }
}

#endif
