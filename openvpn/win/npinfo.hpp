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

// Get info about named pipe peer

#ifndef OPENVPN_WIN_NPINFO_H
#define OPENVPN_WIN_NPINFO_H

#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/abort.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/win/winerr.hpp>
#include <openvpn/win/scoped_handle.hpp>
#include <openvpn/win/secattr.hpp>

namespace openvpn {
  namespace Win {
    struct NamedPipeImpersonate
    {
      OPENVPN_EXCEPTION(named_pipe_impersonate);

      NamedPipeImpersonate(const HANDLE pipe)
      {
	if (!::ImpersonateNamedPipeClient(pipe))
	  {
	    const Win::LastError err;
	    OPENVPN_THROW(named_pipe_impersonate, "ImpersonateNamedPipeClient failed: " << err.message());
	  }
      }

      ~NamedPipeImpersonate()
      {
	if (!::RevertToSelf())
	  {
	    OPENVPN_LOG("NamedPipeImpersonate: RevertToSelf failed, must abort");
	    std::abort();
	  }
      }
    };

    struct NamedPipePeerInfo
    {
      OPENVPN_EXCEPTION(npinfo_error);

      // Get process handle given PID.
      static Win::ScopedHANDLE get_process(const ULONG pid, const bool limited)
      {
	// open process
	Win::ScopedHANDLE proc(::OpenProcess(
#if _WIN32_WINNT >= 0x0600 // Vista and higher
	    limited ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_ALL_ACCESS,
#else
	    PROCESS_ALL_ACCESS,
#endif
	    FALSE,
	    pid));
	if (!proc.defined())
	  {
	    const Win::LastError err;
	    OPENVPN_THROW(npinfo_error, "OpenProcess failed: " << err.message());
	  }
	return proc;
      }

      static std::string send_handle(const HANDLE handle, const HANDLE process)
      {
	HANDLE remote_handle;
	if (!::DuplicateHandle(GetCurrentProcess(),
			       handle,
			       process,
			       &remote_handle,
			       0,
			       FALSE,
			       DUPLICATE_SAME_ACCESS))
	  {
	    const Win::LastError err;
	    OPENVPN_THROW(npinfo_error, "DuplicateHandle failed: " << err.message());
	  }
	const Buffer hb((unsigned char *)&remote_handle, sizeof(remote_handle), true);
	return render_hex_generic(hb);
      }

#if _WIN32_WINNT >= 0x0600 // Vista and higher

      // Servers must call this method to modify their process
      // access rights to grant clients the
      // PROCESS_QUERY_LIMITED_INFORMATION right, so that clients
      // can validate the server's exe path via get_exe_path().
      static void allow_client_query()
      {
	SecurityAttributes sa(
          "D:"                         // discretionary ACL
	  "(A;OICI;0x1000;;;S-1-1-0)"  // allow PROCESS_QUERY_LIMITED_INFORMATION access to Everyone
	  ,
	  false,
	  "client query");

	ACL* dacl;
	BOOL bDaclPresent, bDaclDefaulted;
	if (!::GetSecurityDescriptorDacl(sa.sa.lpSecurityDescriptor,
					 &bDaclPresent,
					 &dacl,
					 &bDaclDefaulted))
	  {
	    const Win::LastError err;
	    OPENVPN_THROW(npinfo_error, "allow_client_query: GetSecurityDescriptorDacl failed: " << err.message());
	  }
	if (!bDaclPresent)
	  OPENVPN_THROW(npinfo_error, "allow_client_query: missing DACL");
	const DWORD ssi_status = ::SetSecurityInfo(
	    ::GetCurrentProcess(),
	    SE_KERNEL_OBJECT,
	    DACL_SECURITY_INFORMATION,
	    NULL,
	    NULL,
	    dacl,
	    NULL);
	if (ssi_status != ERROR_SUCCESS)
	  {
	    const Win::Error err(ssi_status);
	    OPENVPN_THROW(npinfo_error, "allow_client_query: SetSecurityInfo failed: " << err.message());
	  }
      }

      // Get PID of process at other end of named pipe
      static ULONG get_pid(const HANDLE np_handle, const bool client)
      {
	ULONG pid = 0;
	if (client)
	  {
	    if (!::GetNamedPipeClientProcessId(np_handle, &pid))
	      {
		const Win::LastError err;
		OPENVPN_THROW(npinfo_error, "GetNamedPipeClientProcessId failed: " << err.message());
	      }
	  }
	else
	  {
	    if (!::GetNamedPipeServerProcessId(np_handle, &pid))
	      {
		const Win::LastError err;
		OPENVPN_THROW(npinfo_error, "GetNamedPipeServerProcessId failed: " << err.message());
	      }
	  }
	return pid;
      }

      // Get exe path given process handle.
      static std::wstring get_exe_path(const HANDLE proc)
      {
	// get exe path
	const size_t exe_cap = 256;
	wchar_t exe[exe_cap];
	DWORD exe_size = exe_cap;
	if (!::QueryFullProcessImageNameW(proc, 0, exe, &exe_size))
	  {
	    const Win::LastError err;
	    OPENVPN_THROW(npinfo_error, "QueryFullProcessImageNameW failed: " << err.message());
	  }
	return std::wstring(exe, exe_size);
      }

#endif
    };

#if _WIN32_WINNT >= 0x0600 // Vista and higher

    // Used by server to get info about clients
    struct NamedPipePeerInfoClient : public NamedPipePeerInfo
    {
      NamedPipePeerInfoClient(const HANDLE handle)
      {
	const ULONG pid = get_pid(handle, true);
	Win::ScopedHANDLE proc = get_process(pid, false);
	exe_path = get_exe_path(proc());
      }

      std::wstring exe_path;
    };

    // Used by clients to get info about the server
    struct NamedPipePeerInfoServer : public NamedPipePeerInfo
    {
      NamedPipePeerInfoServer(const HANDLE handle)
      {
	const ULONG pid = get_pid(handle, false);
	Win::ScopedHANDLE proc = get_process(pid, true);
	exe_path = get_exe_path(proc());
      }

      std::wstring exe_path;
    };

#endif

  }
}

#endif
