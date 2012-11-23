//
//  macaddr.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
