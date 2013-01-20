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
  }
}

#endif
