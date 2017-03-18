//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// A null Asio unit of work, that prevents the Asio event loop from
// exiting.

#ifndef OPENVPN_COMMON_ASIOWORK_H
#define OPENVPN_COMMON_ASIOWORK_H

#include <asio.hpp>

namespace openvpn {
  class AsioWork
  {
  public:
    AsioWork(asio::io_context& io_context)
      : work(asio::make_work_guard(io_context))
    {
    }

  private:
    asio::executor_work_guard<asio::io_context::executor_type> work;
  };
}

#endif
