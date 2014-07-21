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
