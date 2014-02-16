//
//  tunpersist.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TUN_PERSIST_TUNPERSIST_H
#define OPENVPN_TUN_PERSIST_TUNPERSIST_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/destruct.hpp>
#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/tun/builder/capture.hpp>

namespace openvpn {

  // TunPersistTemplate is used client-side to store the underlying tun
  // interface fd/handle.  It also implements logic for the persist-tun
  // directive.  SCOPED_OBJ is generally a ScopedFD (unix) or a
  // ScopedHANDLE (Windows).  It can also be a ScopedAsioStream.
  template <typename SCOPED_OBJ>
  class TunPersistTemplate : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<TunPersistTemplate> Ptr;

    TunPersistTemplate(const bool enable_persistence, const bool retain_obj, TunBuilderBase* tb)
      : enable_persistence_(enable_persistence),
	retain_obj_(retain_obj),
	tb_(tb),
	use_persisted_tun_(false)
    {
    }

    // Current persisted tun fd/handle
    typename SCOPED_OBJ::base_type obj() const
    {
      return obj_();
    }

    // Current persisted state
    const TunProp::State::Ptr& state() const
    {
      return state_;
    }

    ~TunPersistTemplate()
    {
      close();
    }

    void close()
    {
      if (tb_)
	tb_->tun_builder_teardown();
      if (retain_obj_)
	obj_.release();
      else
	{
	  close_destructor();
	  obj_.close();
	}
      state_.reset();
      options_ = "";
    }

    bool destructor_defined() const
    {
      return bool(destruct_);
    }

    // destruct object performs cleanup prior to TAP device
    // HANDLE close, such as removing added routes.
    void add_destructor(const DestructorBase::Ptr& destruct)
    {
      close_destructor();
      destruct_ = destruct;
    }

    void close_destructor()
    {
      if (destruct_)
	{
	  destruct_->destroy();
	  destruct_.reset();
	}
    }

    // Current persisted options
    const std::string& options()
    {
      return options_;
    }

    // Return true if we should use previously persisted
    // tun socket descriptor/handle
    bool use_persisted_tun(const IP::Addr server_addr,
			   const TunProp::Config& tun_prop,
			   const OptionList& opt)
    {
#if OPENVPN_DEBUG_TUN_BUILDER > 0
      {
	TunBuilderCapture::Ptr capture = new TunBuilderCapture();
	try {
	  TunProp::configure_builder(capture.get(), NULL, NULL, server_addr, tun_prop, opt, true);
	  OPENVPN_LOG("*** TUN BUILDER CAPTURE" << std::endl << capture->to_string());
	}
	catch (const std::exception& e)
	  {
	    OPENVPN_LOG("*** TUN BUILDER CAPTURE ERROR: " << e.what());
	  }
      }
#endif

      // In tun_persist mode, capture tun builder settings so we can
      // compare them to previous persisted settings.
      if (enable_persistence_)
	{
	  copt_.reset(new TunBuilderCapture());
	  try {
	    TunProp::configure_builder(copt_.get(), NULL, NULL, server_addr, tun_prop, opt, true);
	  }
	  catch (const std::exception&)
	    {
	      copt_.reset();
	    }
	}

      // Check if previous tun session matches properties of to-be-created session
      use_persisted_tun_ = (obj_.defined()
			    && copt_
			    && !options_.empty()
			    && options_ == copt_->to_string());
      return use_persisted_tun_;
    }

    // Possibly save tunnel fd/handle, state, and options.
    bool persist_tun_state(const typename SCOPED_OBJ::base_type obj,
			   const TunProp::State::Ptr& state)
    {
      if (!enable_persistence_ || !use_persisted_tun_)
	{
	  save_replace_sock(obj);
	}
      if (enable_persistence_ && copt_ && !use_persisted_tun_)
	{
	  state_ = state;
	  options_ = copt_->to_string();
	  return true;
	}
      else
	return false;
    }

  private:
    void save_replace_sock(const typename SCOPED_OBJ::base_type obj)
    {
      if (retain_obj_)
	obj_.replace(obj);
      else
	obj_.reset(obj);
    }

    const bool enable_persistence_;
    const bool retain_obj_;
    TunBuilderBase * const tb_;
    SCOPED_OBJ obj_;
    TunProp::State::Ptr state_;
    std::string options_;
    DestructorBase::Ptr destruct_;

    TunBuilderCapture::Ptr copt_;
    bool use_persisted_tun_;
  };

}
#endif
