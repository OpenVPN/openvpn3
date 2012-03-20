#ifndef OPENVPN_OPTIONS_CLIOPTHELPER_H
#define OPENVPN_OPTIONS_CLIOPTHELPER_H

#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/string.hpp>

namespace openvpn {
  namespace ClientOptionHelper {
    inline bool is_external_pki(const OptionList& options)
    {
      const Option* epki = options.get_ptr("EXTERNAL_PKI");
      if (epki)
	return string::is_true(epki->get_optional(1));
      else
	{
	  const Option* cert = options.get_ptr("cert");
	  const Option* key = options.get_ptr("key");
	  return !cert || !key;
	}
    }

    inline bool is_autologin(const OptionList& options)
    {
      const Option* autologin = options.get_ptr("AUTOLOGIN");
      if (autologin)
	return string::is_true(autologin->get_optional(1));
      else
	{
	  const Option* auth_user_pass = options.get_ptr("auth-user-pass");
	  bool ret = !auth_user_pass;
	  if (ret)
	    {
	      // External PKI profiles from AS don't declare auth-user-pass,
	      // and we have no way of knowing if they are autologin unless
	      // we examine their cert, which requires accessing the system-level
	      // cert store on the client.  For now, we are going to assume
	      // that External PKI profiles from the AS are always userlogin,
	      // unless explicitly overriden by AUTOLOGIN above.
	      if (is_external_pki(options))
		return false;
	    }
	  return ret;
	}
    }
  }
}

#endif
