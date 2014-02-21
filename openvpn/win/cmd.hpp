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
#include <vector>

#include <openvpn/common/string.hpp>
#include <openvpn/common/destruct.hpp>
#include <openvpn/win/call.hpp>

namespace openvpn {

  class WinCommandList : public DestructorBase
  {
  public:
    typedef boost::intrusive_ptr<WinCommandList> Ptr;

    struct Cmd
    {
      std::string cmd;
    };

    WinCommandList() : enable_destroy_(false) {}

    void add(const std::string& command)
    {
      Cmd c;
      c.cmd = command;
      commands.push_back(c);
    }

    void execute()
    {
      for (CmdVec::const_iterator i = commands.begin(); i != commands.end(); ++i)
	{
	  const Cmd& c = *i;
	  call(c);
	}
    }

    void enable_destroy(const bool state)
    {
      enable_destroy_ = state;
    }

    virtual void destroy()
    {
      if (enable_destroy_)
	{
	  execute();
	  enable_destroy_ = false;
	}
    }

    void call(const Cmd& cmd)
    {
      OPENVPN_LOG(cmd.cmd);
      std::string out = Win::call(cmd.cmd);
      string::trim_crlf(out);
      OPENVPN_LOG(out);
    }

  private:
    typedef std::vector<Cmd> CmdVec;

    CmdVec commands;
    bool enable_destroy_;
  };

}

#endif
