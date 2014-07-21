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

#ifndef OPENVPN_ADDR_MACADDR_H
#define OPENVPN_ADDR_MACADDR_H

#include <ostream>
#include <cstring>
#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/ostream.hpp>
#include <openvpn/common/hexstr.hpp>

namespace openvpn {

  // Fundamental class for representing an ethernet MAC address.

  class MACAddr {
  public:
    MACAddr()
    {
      std::memset(addr_, 0, sizeof(addr_));
    }

    void reset(const unsigned char *addr)
    {
      std::memcpy(addr_, addr, sizeof(addr_));
    }

    std::string to_string() const
    {
      std::string ret;
      ret.reserve(sizeof(addr_)*3);
      size_t size = sizeof(addr_);
      const unsigned char *data = addr_;
      while (size--)
	{
	  const unsigned char c = *data++;
	  ret += render_hex_char(c >> 4);
	  ret += render_hex_char(c & 0x0F);
	  if (size)
	    ret += ':';
	}
    return ret;
    }

  private:
    unsigned char addr_[6];
  };

  OPENVPN_OSTREAM(MACAddr, to_string)

} // namespace openvpn

#endif // OPENVPN_ADDR_MACADDR_H
