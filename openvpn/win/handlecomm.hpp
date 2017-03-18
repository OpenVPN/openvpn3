//
//  handlecomm.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//  All rights reserved.
//

#ifndef OPENVPN_WIN_HANDLECOMM_H
#define OPENVPN_WIN_HANDLECOMM_H

#include <windows.h>

#include <openvpn/buffer/bufhex.hpp>
#include <openvpn/win/winerr.hpp>

namespace openvpn {
  namespace Win {
    namespace HandleComm {

      OPENVPN_EXCEPTION(handle_comm);

      // Duplicate a local handle into the address space of a
      // remote process and return as a hex string that can be
      // communicated across a process boundary.
      inline std::string send_handle(const HANDLE handle,
				     const HANDLE remote_process)
      {
	HANDLE remote_handle;
	if (!::DuplicateHandle(GetCurrentProcess(),
			       handle,
			       remote_process,
			       &remote_handle,
			       0,
			       FALSE,
			       DUPLICATE_SAME_ACCESS))
	  {
	    const Win::LastError err;
	    OPENVPN_THROW(handle_comm, "send_handle: DuplicateHandle failed: " << err.message());
	  }
	return BufHex::render(remote_handle);
      }

      // Duplicate a remote handle (specified as a hex string) into
      // the address space of the local process.
      inline HANDLE receive_handle(const std::string& remote_handle_hex,
				   const HANDLE remote_process)
      {
	const HANDLE remote_handle = BufHex::parse<HANDLE>(remote_handle_hex, "receive_handle");
	HANDLE local_handle;
	if (!::DuplicateHandle(remote_process,
			       remote_handle,
			       GetCurrentProcess(),
			       &local_handle,
			       0,
			       FALSE,
			       DUPLICATE_SAME_ACCESS))
	  {
	    const Win::LastError err;
	    OPENVPN_THROW(handle_comm, "receive_handle: DuplicateHandle failed: " << err.message());
	  }
	return local_handle;
      }

    }
  }
}

#endif
