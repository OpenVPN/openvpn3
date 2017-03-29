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

#ifndef OPENVPN_ASIO_ASIOSTOP_H
#define OPENVPN_ASIO_ASIOSTOP_H

#include <asio.hpp>

#include <openvpn/common/stop.hpp>

namespace openvpn {
  class AsioStopScope : public Stop::Scope
  {
  public:
    AsioStopScope(asio::io_context& io_context,
		  Stop* stop,
		  std::function<void()>&& method)
      : Stop::Scope(stop, post_method(io_context, std::move(method)))
    {
    }

  private:
    static std::function<void()> post_method(asio::io_context& io_context, std::function<void()>&& method)
    {
      return [&io_context, method=std::move(method)]()
	{
	  asio::post(io_context, std::move(method));
	};
    }
  };

}

#endif
