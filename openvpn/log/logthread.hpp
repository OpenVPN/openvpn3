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

// This is a general-purpose logging framework that allows for OPENVPN_LOG and
// OPENVPN_LOG_NTNL macros to dispatch logging data to a thread-local handler.

#ifndef OPENVPN_LOG_LOGTHREAD_H
#define OPENVPN_LOG_LOGTHREAD_H

#include <string>
#include <sstream>

#include <openvpn/common/types.hpp>
#include <openvpn/common/thread.hpp>

// Define these parameters before including this header:

// OPENVPN_LOG_CLASS -- client class that exposes a log() method
// OPENVPN_LOG_INFO  -- converts a log string to the form that should be passed to log()

#ifndef OPENVPN_LOG_CLASS
#error OPENVPN_LOG_CLASS must be defined
#endif

#ifndef OPENVPN_LOG_INFO
#error OPENVPN_LOG_INFO must be defined
#endif

# define OPENVPN_LOG(args) \
  do { \
    if (openvpn::Log::global_log != NULL) { \
      std::ostringstream _ovpn_log; \
      _ovpn_log << args << std::endl; \
      (openvpn::Log::Context::obj()->log(OPENVPN_LOG_INFO(_ovpn_log.str()))); \
    } \
  } while (0)

// like OPENVPN_LOG but no trailing newline
#define OPENVPN_LOG_NTNL(args) \
  do { \
    if (openvpn::Log::global_log != NULL) { \
      std::ostringstream _ovpn_log; \
      _ovpn_log << args; \
      (openvpn::Log::Context::obj()->log(OPENVPN_LOG_INFO(_ovpn_log.str()))); \
    } \
  } while (0)

namespace openvpn {
  namespace Log {

    boost::asio::detail::tss_ptr<OPENVPN_LOG_CLASS> global_log; // GLOBAL

    struct Context
    {
      class Wrapper
      {
      public:
	Wrapper() : log(obj()) {}
      private:
	friend struct Context;
	OPENVPN_LOG_CLASS *log;
      };

      Context(const Wrapper& wrap)
      {
	global_log = wrap.log;
      }

      Context(OPENVPN_LOG_CLASS *cli)
      {
	global_log = cli;
      }

      ~Context()
      {
	global_log = NULL;
      }

      static OPENVPN_LOG_CLASS* obj()
      {
	return global_log;
      }
    };

  }
}

#endif
