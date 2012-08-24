//
//  mode.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_MODE_H
#define OPENVPN_COMMON_MODE_H

namespace openvpn {
  class Mode
  {
  public:
    enum Type {
      CLIENT,
      SERVER,
    };

    Mode() : type_(CLIENT) {}
    explicit Mode(const Type t) : type_(t) {}

    bool is_server() const { return type_ == SERVER; }
    bool is_client() const { return type_ == CLIENT; }

    bool operator==(const Mode& other)
    {
      return type_ == other.type_;
    }

    bool operator!=(const Mode& other)
    {
      return type_ != other.type_;
    }

    const char *str() const
    {
      switch (type_)
	{
	case CLIENT:
	  return "CLIENT";
	case SERVER:
	  return "SERVER";
	default:
	  return "UNDEF_MODE";
	}
    }

  private:
    Type type_;
  };
} // namespace openvpn

#endif // OPENVPN_COMMON_MODE_H
