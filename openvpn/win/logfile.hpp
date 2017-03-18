//
//  logfile.hpp
//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//  All rights reserved.
//

#ifndef OPENVPN_WIN_LOGFILE_H
#define OPENVPN_WIN_LOGFILE_H

#include <openvpn/log/logbase.hpp>
#include <openvpn/win/logutil.hpp>

namespace openvpn {
  namespace Win {

    class LogFile : public LogBase
    {
    public:
      typedef RCPtr<LogFile> Ptr;

      LogFile(const std::string& fn,
	      const std::string& sddl_string,
	      bool append)
	: log_handle(LogUtil::create_file(fn, sddl_string, append)),
	  log_context(this)
      {
      }

      virtual void log(const std::string& str) override
      {
	LogUtil::log(log_handle(), str);
      }

    private:
      ScopedHANDLE log_handle;
      Log::Context log_context; // must be initialized last
    };

  }
}

#endif
