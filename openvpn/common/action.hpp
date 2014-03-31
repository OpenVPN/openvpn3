//
//  action.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//


#ifndef OPENVPN_COMMON_ACTION_H
#define OPENVPN_COMMON_ACTION_H

#include <vector>
#include <string>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/destruct.hpp>

namespace openvpn {

  struct Action : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<Action> Ptr;

    virtual void execute() = 0;
    virtual std::string to_string() const = 0;
    virtual ~Action() {}
  };

  class ActionList : public std::vector<Action::Ptr>, public DestructorBase
  {
  public:
    typedef boost::intrusive_ptr<ActionList> Ptr;

    ActionList(const size_t capacity=16)
      : enable_destroy_(false),
	halt_(false)
    {
      reserve(capacity);
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
	  for (const_iterator i = begin(); i != end(); ++i)
	    {
	      const Action& a = **i;
	      if (a.to_string() == cmp)
		return true;
	    }
	}
      return false;
    }

    bool execute()
    {
      for (iterator i = begin(); i != end(); ++i)
	{
	  Action& a = **i;
	  if (halt_)
	    return false;
	  try {
	    a.execute();
	  }
	  catch (const std::exception& e)
	    {
	      OPENVPN_LOG("action exception: " << e.what());
	    }
	}
      return true;
    }

    void enable_destroy(const bool state)
    {
      enable_destroy_ = state;
    }

    void halt()
    {
      halt_ = true;
    }

    virtual void destroy()
    {
      if (enable_destroy_)
	{
	  execute();
	  enable_destroy_ = false;
	}
    }

  private:
    bool enable_destroy_;
    volatile bool halt_;
  };

}

#endif
