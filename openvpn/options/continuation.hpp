#ifndef OPENVPN_OPTIONS_CONTINUATION_H
#define OPENVPN_OPTIONS_CONTINUATION_H

#include <openvpn/common/exception.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn {

  // Aggregate pushed option continuations into a singular option list.
  // Note that map is not updated until list is complete.
  class OptionListContinuation : public OptionList
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(olc_complete); // add called when object is already complete

    OptionListContinuation()
      : partial_(false), complete_(false) {}

    // call with option list fragments
    void add(const OptionList& other)
    {
      if (!complete_)
	{
	  partial_ = true;
	  extend(other);
	  if (!continuation(other))
	    {
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
      return o && o->size() >= 2 && (*o)[1] == "2";
    }

    bool partial_;
    bool complete_;
  };

} // namespace openvpn

#endif // OPENVPN_OPTIONS_CONTINUATION_H
