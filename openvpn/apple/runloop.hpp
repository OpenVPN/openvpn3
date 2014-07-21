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

#ifndef OPENVPN_APPLE_RUNLOOP_H
#define OPENVPN_APPLE_RUNLOOP_H

#include <openvpn/applecrypto/cf/cf.hpp>

namespace openvpn {
  namespace CF {
    OPENVPN_CF_WRAP(RunLoop, runloop_cast, CFRunLoopRef, CFRunLoopGetTypeID);
    OPENVPN_CF_WRAP(RunLoopSource, runloop_source_cast, CFRunLoopSourceRef, CFRunLoopSourceGetTypeID);
  }
}

#endif
