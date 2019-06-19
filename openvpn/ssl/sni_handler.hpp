//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2019 OpenVPN Inc.
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

#pragma once

#include <string>
#include <memory>

#include <openvpn/ssl/sslapi.hpp>

namespace openvpn {
  namespace SNI {

    // Abstract base class used to provide an SNI handler
    class HandlerBase
    {
    public:
      // Return a new SSLFactoryAPI for this SNI name.
      // Return SSLFactoryAPI::Ptr() if sni_name is not recognized.
      // The caller guarantees that sni_name is valid UTF-8 and
      // doesn't contain any control characters.
      virtual SSLFactoryAPI::Ptr sni_hello(const std::string& sni_name, SSLConfigAPI::Ptr default_factory) const = 0;

      virtual ~HandlerBase() {}
    };

  }
}
