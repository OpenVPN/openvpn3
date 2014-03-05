//
//  sleep.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_WIN_SLEEP_H
#define OPENVPN_WIN_SLEEP_H

#include <windows.h>

#include <string>

#include <openvpn/common/action.hpp>
#include <openvpn/common/format.hpp>

namespace openvpn {

  class WinSleep : public Action
  {
  public:
    typedef boost::intrusive_ptr<WinSleep> Ptr;

    WinSleep(DWORD dwMilliseconds_arg)
      : dwMilliseconds(dwMilliseconds_arg)
    {
    }

    virtual void execute()
    {
      OPENVPN_LOG(to_string());
      Sleep(dwMilliseconds);
    }

    virtual std::string to_string() const
    {
      return "Sleeping for " + openvpn::to_string(dwMilliseconds) + " milliseconds...";
    }

  private:
    DWORD dwMilliseconds;
  };

}
#endif
