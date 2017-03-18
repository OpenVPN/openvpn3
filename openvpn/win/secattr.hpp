//
//  secattr.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//  All rights reserved.
//

// windows SECURITY_ATTRIBUTES utilities

#ifndef OPENVPN_WIN_SECATTR_H
#define OPENVPN_WIN_SECATTR_H

#include <windows.h>
#include <sddl.h>

#include <openvpn/common/exception.hpp>
#include <openvpn/win/winerr.hpp>

namespace openvpn {
  namespace Win {

    struct SecurityAttributes
    {
      OPENVPN_EXCEPTION(win_sec_attr);

      SecurityAttributes(const std::string& sddl_string,
			 const bool inherit,
			 const std::string& title)
      {
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = inherit ? TRUE : FALSE;
	sa.lpSecurityDescriptor = nullptr;
	if (!sddl_string.empty())
	  {
	    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorA(
	        sddl_string.c_str(),
		SDDL_REVISION_1,
		&sa.lpSecurityDescriptor,    // allocates memory
		NULL))
	      {
		const Win::LastError err;
		OPENVPN_THROW(win_sec_attr, "failed to create security descriptor for " << title << " : " << err.message());
	      }
	  }
      }

      ~SecurityAttributes()
      {
	::LocalFree(sa.lpSecurityDescriptor);
      }

      SECURITY_ATTRIBUTES sa;
    };

  }
}

#endif
