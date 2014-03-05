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

  class ActionList : public DestructorBase
  {
    typedef std::vector<Action::Ptr> ActionVec;

  public:
    typedef boost::intrusive_ptr<ActionList> Ptr;

    ActionList(const size_t capacity=16)
      : enable_destroy_(false),
	halt_(false)
    {
      actions.reserve(capacity);
    }

    void add(const Action::Ptr& action)
    {
      actions.push_back(action);
    }

    bool execute()
    {
      for (ActionVec::iterator i = actions.begin(); i != actions.end(); ++i)
	{
	  Action& a = **i;
	  if (halt_)
	    return false;
	  a.execute();
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
    ActionVec actions;
    bool enable_destroy_;
    volatile bool halt_;
  };

}

#endif
