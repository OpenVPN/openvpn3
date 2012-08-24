//
//  ip.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
