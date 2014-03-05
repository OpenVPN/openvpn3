//
//  command.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_WIN_CMD_H
#define OPENVPN_WIN_CMD_H

#include <windows.h>

#include <string>

#include <openvpn/common/string.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/win/call.hpp>

namespace openvpn {

  class WinCmd : public Action
  {
  public:
    typedef boost::intrusive_ptr<WinCmd> Ptr;

    WinCmd(const std::string& command)
      : cmd(command)
    {
    }

    virtual void execute()
    {
      OPENVPN_LOG(cmd);
      std::string out = Win::call(cmd);
      string::trim_crlf(out);
      OPENVPN_LOG(out);
    }

    virtual std::string to_string() const
    {
      return cmd;
    }

  private:
    std::string cmd;
  };

}
#endif
