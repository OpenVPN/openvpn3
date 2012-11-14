//
//  continuation.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_OPTIONS_CONTINUATION_H
#define OPENVPN_OPTIONS_CONTINUATION_H

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn {

  struct PushOptionsBase : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<PushOptionsBase> Ptr;

    OptionList multi;
    OptionList singleton;
  };

  // Aggregate pushed option continuations into a singular option list.
  // Note that map is not updated until list is complete.
  class OptionListContinuation : public OptionList
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(olc_complete); // add called when object is already complete

    OptionListContinuation(const PushOptionsBase::Ptr& push_base_arg)
      : partial_(false),
	complete_(false),
	push_base(push_base_arg)
    {
      if (push_base)
	extend(push_base->multi);
    }

    // call with option list fragments
    void add(const OptionList& other)
    {
      if (!complete_)
	{
	  partial_ = true;
	  extend(other);
	  if (!continuation(other))
	    {
	      if (push_base)
		extend_nonexistent(push_base->singleton);
	      update_map();
	      complete_ = true;
	    }
	}
      else
	throw olc_complete();
    }

    // returns true if add() was called at least once
    bool partial() const { return partial_; }

    // returns true if option list is complete
    bool complete() const { return complete_; }

  private:
    static bool continuation(const OptionList& opt)
    {
      const Option *o = opt.get_ptr("push-continuation");
      return o && o->size() >= 2 && o->ref(1) == "2";
    }

    bool partial_;
    bool complete_;

    PushOptionsBase::Ptr push_base;
  };

} // namespace openvpn

#endif // OPENVPN_OPTIONS_CONTINUATION_H
