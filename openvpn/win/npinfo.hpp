//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#pragma once

// Get info about named pipe peer

#include <cstdlib> // defines std::abort()
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/win/winerr.hpp>
#include <openvpn/win/scoped_handle.hpp>
#include <openvpn/win/secattr.hpp>

namespace openvpn::Win {
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
            limited ? (PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE) : PROCESS_ALL_ACCESS,
            FALSE,
            pid));
        if (!proc.defined())
        {
            const Win::LastError err;
            OPENVPN_THROW(npinfo_error, "OpenProcess failed: " << err.message());
        }
        return proc;
    }

    // Servers must call this method to modify their process
    // access rights to grant clients the
    // PROCESS_QUERY_LIMITED_INFORMATION right, so that clients
    // can validate the server's exe path via get_exe_path().
    static void allow_client_query()
    {
        SecurityAttributes sa(
            "D:"                          // discretionary ACL
            "(A;OICI;0x101000;;;S-1-1-0)" // grant PROCESS_QUERY_LIMITED_INFORMATION and SYNCHRONIZE access to Everyone
            ,
            false,
            "client query");

        ACL *dacl;
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
};

struct NamedPipePeerInfoCS : public NamedPipePeerInfo
{
    NamedPipePeerInfoCS(const HANDLE handle, const bool client)
    {
        const ULONG pid = get_pid(handle, client);
        proc = get_process(pid, !client);
        exe_path = get_exe_path(proc());
    }

    Win::ScopedHANDLE proc;
    std::wstring exe_path;
};

// Used by server to get info about clients
struct NamedPipePeerInfoClient : public NamedPipePeerInfoCS
{
    NamedPipePeerInfoClient(const HANDLE handle)
        : NamedPipePeerInfoCS(handle, true)
    {
    }
};

// Used by clients to get info about the server
struct NamedPipePeerInfoServer : public NamedPipePeerInfoCS
{
    NamedPipePeerInfoServer(const HANDLE handle)
        : NamedPipePeerInfoCS(handle, false)
    {
    }
};

} // namespace openvpn::Win
