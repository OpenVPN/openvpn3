//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Inc.
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

// Define the ICMP header

#ifndef OPENVPN_IP_ICMP_H
#define OPENVPN_IP_ICMP_H

#include <cstdint> // for std::uint32_t, uint16_t, uint8_t

#include <openvpn/ip/ip.hpp>

#pragma pack(push)
#pragma pack(1)

namespace openvpn {
  struct ICMP {
    enum {
      ECHO_REPLY = 0,
      ECHO_REQUEST = 8,
    };

    struct IPHeader head;

    std::uint8_t type;
    std::uint8_t code;
    std::uint16_t checksum;

    union {
      struct {
	std::uint16_t id;
	std::uint16_t seq_num;
      } echo;
    } hd;
  };
}

#pragma pack(pop)

#endif
