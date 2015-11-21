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

#ifndef OPENVPN_COMMON_STOP_H
#define OPENVPN_COMMON_STOP_H

#include <vector>
#include <functional>
#include <utility>
#include <mutex>

namespace openvpn {
  class Stop
  {
  public:
    class Scope
    {
      friend Stop;

    public:
      Scope(Stop* stop_arg, std::function<void()>&& method_arg)
	: stop(stop_arg),
	  index(0),
	  method(std::move(method_arg))
      {
	if (stop)
	  {
	    std::lock_guard<std::recursive_mutex> lock(stop->mutex);
	    index = stop->scopes.size();
	    stop->scopes.push_back(this);
	  }
      }

      ~Scope()
      {
	if (stop)
	  {
	    std::lock_guard<std::recursive_mutex> lock(stop->mutex);
	    if (stop->scopes.size() > index && stop->scopes[index] == this)
	      {
		stop->scopes[index] = nullptr;
		stop->prune();
	      }
	  }
      }

    private:
      Scope(const Scope&) = delete;
      Scope& operator=(const Scope&) = delete;

      Stop* stop;
      size_t index;
      std::function<void()> method;
    };

    Stop()
    {
    }

    void stop()
    {
      std::lock_guard<std::recursive_mutex> lock(mutex);
      while (scopes.size())
	{
	  Scope* scope = scopes.back();
	  scopes.pop_back();
	  if (scope)
	    {
	      scope->stop = nullptr;
	      scope->method();
	    }
	}
    }

  private:
    Stop(const Stop&) = delete;
    Stop& operator=(const Stop&) = delete;

    void prune()
    {
      while (scopes.size() && !scopes.back())
	scopes.pop_back();
    }

    std::vector<Scope*> scopes;
    std::recursive_mutex mutex;
  };

}

#endif
