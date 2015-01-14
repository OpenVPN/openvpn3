//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

#ifndef OPENVPN_COMMON_DAEMON_H
#define OPENVPN_COMMON_DAEMON_H

#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>

#include <string>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/format.hpp>
#include <openvpn/common/file.hpp>

namespace openvpn {

  OPENVPN_EXCEPTION(daemon_err);

  inline void redir_std(const std::string& fn, const bool append)
  {
    // open logfile
    const int log = open(fn.c_str(),
			 O_CREAT | O_WRONLY | (append ? O_APPEND : O_TRUNC),
			 S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (log < 0)
      OPENVPN_THROW(daemon_err, "error opening logfile: " << fn << " : " << std::strerror(errno));

    // redirect stdin to /dev/null
    const int dn = open("/dev/null", O_RDWR, 0);
    if (dn >= 0)
      {
	dup2(dn, 0);
	if (dn > 2)
	  close(dn);
      }

    // redirect stdout/stderr to logfile
    dup2(log, 1);
    dup2(log, 2);
    if (log > 2)
      close(log);
  }

  inline void daemonize(const std::string& log_fn, const bool log_append)
  {
    redir_std(log_fn, log_append);
    if (daemon(1, 1) < 0)
      throw daemon_err("daemon() failed");
  }

  inline void write_pid(const std::string& fn)
  {
    write_string(fn, to_string(getpid()) + '\n');
  }
}

#endif
