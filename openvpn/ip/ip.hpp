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

// Define the IP protocol header

#ifndef OPENVPN_IP_IP_H
#define OPENVPN_IP_IP_H

#include <boost/cstdint.hpp> // for boost::uint32_t, uint16_t, uint8_t

#pragma pack(push)
#pragma pack(1)

namespace openvpn {
  struct IPHeader
  {
    static unsigned int version(const boost::uint8_t version_len)
    {
      return (version_len >> 4) & 0x0F;
    }
    static unsigned int length(const boost::uint8_t version_len)
    {
      return (version_len & 0x0F) << 2;
    }
    boost::uint8_t    version_len;

    boost::uint8_t    tos;
    boost::uint16_t   tot_len;
    boost::uint16_t   id;

    enum {
      OFFMASK=0x1fff,
    };
    boost::uint16_t   frag_off;

    boost::uint8_t    ttl;

    enum {
      IGMP=2, /* IGMP protocol */
      TCP=6,  /* TCP protocol */
      UDP=17, /* UDP protocol */
    };
    boost::uint8_t    protocol;

    boost::uint16_t   check;
    boost::uint32_t   saddr;
    boost::uint32_t   daddr;
    /*The options start here. */
  };

#pragma pack(pop)

}

#endif
