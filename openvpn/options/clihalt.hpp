//
//  clihalt.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_OPTIONS_CLIHALT_H
#define OPENVPN_OPTIONS_CLIHALT_H

#include <string>
#include <sstream>
#include <vector>

#include <boost/algorithm/string.hpp> // for boost::algorithm::starts_with

#include <openvpn/common/exception.hpp>
#include <openvpn/common/split.hpp>

// Process halt/restart messages from server:
//   HALT,<client_reason>        -> disconnect
//   RESTART,<client_reason>     -> restart with reason, don't preserve session ID
//   RESTART,[P]:<client_reason> -> restart with reason, do preserve session ID

namespace openvpn {
  class ClientHalt
  {
    typedef std::vector<std::string> StringList;

  public:
    OPENVPN_SIMPLE_EXCEPTION(client_halt_error);

    ClientHalt(const std::string& msg)
      : restart_(false), psid_(false)
    {
      // get operator (halt or restart)
      StringList sl;
      parse_msg(sl, msg);
      if (is_halt(sl))
	;
      else if (is_restart(sl))
	restart_ = true;
      else
	throw client_halt_error();

      // get flags and reason
      if (sl.size() >= 2)
	{
	  size_t reason_pos = 0;
	  if (restart_ && boost::algorithm::starts_with(sl[1], "[P]:"))
	    {
	      psid_ = true;
	      reason_pos = 4;
	    }
	  reason_ = sl[1].substr(reason_pos);
	}
    }

    static bool match(const std::string& msg)
    {
      StringList sl;
      parse_msg(sl, msg);
      return is_halt(sl) || is_restart(sl);
    }

    // returns true for restart, false for halt
    bool restart() const { return restart_; }

    // returns true if session ID should be preserved
    bool psid() const { return psid_; }

    // returns user-visible reason string
    const std::string& reason() const { return reason_; }

    std::string render() const {
      std::ostringstream os;
      os << (restart_ ? "RESTART" : "HALT") << " psid=" << psid_ << " reason='" << reason_ << '\'';
      return os.str();
    }

  private:
    static void parse_msg(StringList& sl, const std::string& msg)
    {
      sl.reserve(2);
      Split::by_char_void<StringList, NullLex, Split::NullLimit>(sl, msg, ',', 0, 1);
    }

    static bool is_halt(const StringList& sl)
    {
      return sl.size() >= 1 && sl[0] == "HALT";
    }

    static bool is_restart(const StringList& sl)
    {
      return sl.size() >= 1 && sl[0] == "RESTART";
    }

    bool restart_;
    bool psid_;
    std::string reason_;
  };
}

#endif
