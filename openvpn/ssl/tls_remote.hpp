//
//  tls_remote.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// test certificate subject and common name against tls_remote parameter

#ifndef OPENVPN_SSL_TLS_REMOTE_H
#define OPENVPN_SSL_TLS_REMOTE_H

#include <boost/algorithm/string.hpp> // for boost::algorithm::starts_with

#include <cstring>
#include <string>

#include <openvpn/common/string.hpp>

namespace openvpn {
  namespace TLSRemote {
    inline bool test(const std::string& tls_remote, const std::string& subject, const std::string& common_name)
    {
      return tls_remote == subject || boost::algorithm::starts_with(common_name, tls_remote);
    }

    inline void log(const std::string& tls_remote, const std::string& subject, const std::string& common_name)
    {
      OPENVPN_LOG("tls-remote validation" << std::endl << "  tls-remote: '" << tls_remote << '\'' << std::endl << "  Subj: '" << subject << '\'' << std::endl << "  CN: '" << common_name << '\'');
    }

    // modifies x509 name in a way that is compatible with
    // name remapping behavior on OpenVPN 2.x
    inline std::string sanitize_x509_name(const std::string& str)
    {
      std::string ret;
      bool leading_dash = true;
      ret.reserve(str.length());
      for (size_t i = 0; i < str.length(); ++i)
	{
	  const char c = str[i];
	  if (c == '-' && leading_dash)
	    {
	      ret += '_';
	      continue;
	    }
	  leading_dash = false;
	  if ((c >= 'a' && c <= 'z')
	      || (c >= 'A' && c <= 'Z')
	      || (c >= '0' && c <= '9')
	      || c == '_' || c == '-' || c == '.'
	      || c == '@' || c == ':' || c == '/'
	      || c == '=')
	    ret += c;
	  else
	    ret += '_';
	}
      return ret;
    }

    // modifies common name in a way that is compatible with
    // name remapping behavior on OpenVPN 2.x
    inline std::string sanitize_common_name(const std::string& str)
    {
      std::string ret;
      ret.reserve(str.length());
      for (size_t i = 0; i < str.length(); ++i)
	{
	  const char c = str[i];
	  if ((c >= 'a' && c <= 'z')
	      || (c >= 'A' && c <= 'Z')
	      || (c >= '0' && c <= '9')
	      || c == '_' || c == '-' || c == '.'
	      || c == '@' || c == '/')
	    ret += c;
	  else
	    ret += '_';
	}
      return ret;
    }
  }
}

#endif
