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

// execute a Windows command, capture the output

#ifndef OPENVPN_WIN_CALL_H
#define OPENVPN_WIN_CALL_H

#include <windows.h>
#include <shlobj.h>

#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/win/scoped_handle.hpp>

namespace openvpn {
  namespace Win {

    OPENVPN_EXCEPTION(win_call);

    // delete method for CoTask
    template <typename T>
    class FreeCoTask {
    public:
      static void del(T* p)
      {
	CoTaskMemFree(p);
      }
    };

    inline std::string call(const std::string& cmd)
    {
      // split command name from args
      std::string name;
      std::string args;
      const size_t spcidx = cmd.find_first_of(" ");
      if (spcidx != std::string::npos)
	{
	  name = cmd.substr(0, spcidx);
	  if (spcidx+1 < cmd.length())
	    args = cmd.substr(spcidx+1);
	}
      else
	name = cmd;

#if _WIN32_WINNT >= 0x0600
      // get system path (Vista and higher)
      ScopedPtr<wchar_t, FreeCoTask> syspath;
      if (SHGetKnownFolderPath(FOLDERID_System, 0, NULL, syspath.ref()) != S_OK)
	throw win_call("cannot get system path using SHGetKnownFolderPath");
#     define SYSPATH_FMT_CHAR L"s"
#     define SYSPATH_LEN_METH(x) wcslen(x)
#else
      // get system path (XP and higher)
      ScopedPtr<TCHAR, FreeCoTask> syspath(new char[MAX_PATH]);
      if (SHGetFolderPath(NULL, CSIDL_SYSTEM, NULL, 0, syspath()) != S_OK)
	throw win_call("cannot get system path using SHGetFolderPath");
#     define SYSPATH_FMT_CHAR L"S"
#     define SYSPATH_LEN_METH(x) strlen(x)
#endif

      // build command line
      const size_t wcmdlen = SYSPATH_LEN_METH(syspath()) + name.length() + args.length() + 64;
      ScopedPtr<wchar_t, PtrArrayFree> wcmd(new wchar_t[wcmdlen]);
      const char *spc = "";
      if (!args.empty())
	spc = " ";
      _snwprintf(wcmd(), wcmdlen, L"\"%" SYSPATH_FMT_CHAR L"\\%S.exe\"%S%S", syspath(), name.c_str(), spc, args.c_str());
      wcmd()[wcmdlen-1] = 0;
      //wprintf(L"CMD[%d]: %s\n", (int)wcslen(wcmd()), wcmd());
#     undef SYSPATH_FMT_CHAR
#     undef SYSPATH_LEN_METH

      // Set the bInheritHandle flag so pipe handles are inherited.
      SECURITY_ATTRIBUTES saAttr;
      saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
      saAttr.bInheritHandle = TRUE;
      saAttr.lpSecurityDescriptor = NULL;

      // Create a pipe for the child process's STDOUT.
      ScopedHANDLE cstdout_r; // child write side
      ScopedHANDLE cstdout_w; // parent read side
      if (!CreatePipe(cstdout_r.ref(), cstdout_w.ref(), &saAttr, 0))
	throw win_call("cannot create pipe for child stdout");

      // Ensure the read handle to the pipe for STDOUT is not inherited.
      if (!SetHandleInformation(cstdout_r(), HANDLE_FLAG_INHERIT, 0))
	throw win_call("SetHandleInformation failed for child stdout pipe");

      // Set up members of the PROCESS_INFORMATION structure.
      PROCESS_INFORMATION piProcInfo;
      ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

      // Set up members of the STARTUPINFO structure.
      // This structure specifies the STDIN and STDOUT handles for redirection.
      STARTUPINFOW siStartInfo;
      ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
      siStartInfo.cb = sizeof(STARTUPINFO);
      siStartInfo.hStdError = cstdout_w();
      siStartInfo.hStdOutput = cstdout_w();
      siStartInfo.hStdInput = NULL;
      siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

      // Create the child process.
      if (!CreateProcessW(NULL,
			  wcmd(),        // command line
			  NULL,          // process security attributes
			  NULL,          // primary thread security attributes
			  TRUE,          // handles are inherited
			  0,             // creation flags
			  NULL,          // use parent's environment
			  NULL,          // use parent's current directory
			  &siStartInfo,  // STARTUPINFO pointer
			  &piProcInfo))  // receives PROCESS_INFORMATION
	throw win_call("cannot create process");

      // wrap handles to child process and its primary thread.
      ScopedHANDLE process_hand(piProcInfo.hProcess);
      ScopedHANDLE thread_hand(piProcInfo.hThread);

      // close child's end of stdout/stderr pipe
      cstdout_w.close();

      // read child's stdout
      const size_t outbuf_size = 512;
      ScopedPtr<char, PtrArrayFree> outbuf(new char[outbuf_size]);
      std::string out;
      while (true)
	{
	  DWORD dwRead;
	  if (!ReadFile(cstdout_r(), outbuf(), outbuf_size, &dwRead, NULL))
	    break;
	  if (dwRead == 0)
	    break;
	  out += std::string(outbuf(), 0, dwRead);
	}

      // wait for child to exit
      if (WaitForSingleObject(process_hand(), INFINITE) == WAIT_FAILED)
	throw win_call("WaitForSingleObject failed on child process handle");

      return out;
    }
  }
}

#endif
