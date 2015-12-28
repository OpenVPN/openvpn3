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


#ifndef OPENVPN_COMMON_ACTION_H
#define OPENVPN_COMMON_ACTION_H

#include <vector>
#include <string>
#include <ostream>

#ifdef HAVE_JSONCPP
#include "json/json.h"
#endif

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/destruct.hpp>

namespace openvpn {

  struct Action : public RC<thread_unsafe_refcount>
  {
    typedef RCPtr<Action> Ptr;

    virtual void execute(std::ostream& os) = 0;
    virtual std::string to_string() const = 0;
#ifdef HAVE_JSONCPP
    virtual Json::Value to_json() const
    {
      throw Exception("Action::to_json() virtual method not implemented");
    }
#endif
    virtual ~Action() {}
  };

  class ActionList : public std::vector<Action::Ptr>, public DestructorBase
  {
  public:
    typedef RCPtr<ActionList> Ptr;

    ActionList(const size_t capacity=16)
      : enable_destroy_(false),
	halt_(false)
    {
      reserve(capacity);
    }

    void add(Action* action)
    {
      if (action)
	emplace_back(action);
    }

    void add(const Action::Ptr& action)
    {
      if (action)
	push_back(action);
    }

    void add(const ActionList& other)
    {
      insert(end(), other.begin(), other.end());
    }

    bool exists(const Action::Ptr& action) const
    {
      if (action)
	{
	  const std::string cmp = action->to_string();
	  for (auto &a : *this)
	    {
	      if (a->to_string() == cmp)
		return true;
	    }
	}
      return false;
    }

    virtual void execute(std::ostream& os)
    {
      for (auto &a : *this)
	{
	  if (is_halt())
	    return;
	  try {
	    a->execute(os);
	  }
	  catch (const std::exception& e)
	    {
	      os << "action exception: " << e.what() << std::endl;
	    }
	}
    }

    void enable_destroy(const bool state)
    {
      enable_destroy_ = state;
    }

    void halt()
    {
      halt_ = true;
    }

    virtual void destroy(std::ostream& os) override // defined by DestructorBase
    {
      if (enable_destroy_)
	{
	  execute(os);
	  enable_destroy_ = false;
	}
    }

    bool is_halt() const
    {
      return halt_;
    }

  private:
    bool enable_destroy_;
    volatile bool halt_;
  };

  struct ActionListFactory : public RC<thread_unsafe_refcount>
  {
    typedef RCPtr<ActionListFactory> Ptr;

    virtual ActionList::Ptr new_action_list() = 0;
  };
}

#endif
