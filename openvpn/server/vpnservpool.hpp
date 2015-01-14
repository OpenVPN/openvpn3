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

#ifndef OPENVPN_SERVER_VPNSERVPOOL_H
#define OPENVPN_SERVER_VPNSERVPOOL_H

#include <openvpn/common/thread.hpp>
#include <openvpn/server/vpnservnetblock.hpp>
#include <openvpn/addr/pool.hpp>

namespace openvpn {

  // single pool shared across all threads
  class VPNServerNetblockPool : public VPNServerNetblock
  {
  public:
    typedef boost::intrusive_ptr<VPNServerNetblockPool> Ptr;

    VPNServerNetblockPool(const OptionList& opt)
      : VPNServerNetblock(opt, 0)
    {
      pool4.add_range(netblock4().clients);
      pool6.add_range(netblock6().clients);
    }

    IP::Pool pool4;
    IP::Pool pool6;

    Mutex mutex;
  };

}

#endif
