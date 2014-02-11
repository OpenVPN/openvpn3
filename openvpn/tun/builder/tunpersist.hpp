//
//  tunpersist.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TUN_BUILDER_TUNPERSIST_H
#define OPENVPN_TUN_BUILDER_TUNPERSIST_H

#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/tun/builder/capture.hpp>

namespace openvpn {

  // TunPersistTemplate is used in the implementation of the OpenVPN
  // client-side persist-tun directive.
  // SCOPED_OBJ is generally a ScopedFD (unix) or a ScopedHANDLE (Windows).
  template <typename SCOPED_OBJ>
  class TunPersistTemplate : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<TunPersistTemplate> Ptr;

    TunPersistTemplate(const bool retain_obj, TunBuilderBase* tb)
      : retain_obj_(retain_obj), tb_(tb) {}

    bool defined() const
    {
      return obj_.defined();
    }

    bool match(const std::string& options) const
    {
      return options == options_ && !options_.empty();
    }

    void persist(const typename SCOPED_OBJ::base_type obj,
		 const TunProp::State::Ptr& state,
		 const std::string& options)
    {
      if (retain_obj_)
	obj_.replace(obj);
      else
	obj_.reset(obj);
      state_ = state;
      options_ = options;
    }

    typename SCOPED_OBJ::base_type obj() const
    {
      return obj_();
    }

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
	obj_.close();
      state_.reset();
      options_ = "";
    }

    const std::string& options()
    {
      return options_;
    }

  private:
    bool retain_obj_;
    TunBuilderBase* tb_;
    SCOPED_OBJ obj_;
    TunProp::State::Ptr state_;
    std::string options_;
  };

  template <typename SCOPED_OBJ>
  class TunPersistHelper
  {
  public:
    typedef TunPersistTemplate<SCOPED_OBJ> TunPersist;

    TunPersistHelper(const typename TunPersist::Ptr& tun_persist_arg,
		     const TunProp::Config& tun_prop,
		     const OptionList& opt,
		     const IP::Addr server_addr)
      : tun_persist(tun_persist_arg),
	use_persisted_tun_(false)
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
      // compare them to persisted settings.
      if (tun_persist)
	{
	  copt.reset(new TunBuilderCapture());
	  try {
	    TunProp::configure_builder(copt.get(), NULL, NULL, server_addr, tun_prop, opt, true);
	  }
	  catch (const std::exception& e)
	    {
	      copt.reset();
	    }
	}

      // Check if persisted tun session matches properties of to-be-created session
      use_persisted_tun_ = (copt && tun_persist->match(copt->to_string()));
    }

    // New tun properties exactly match persisted tun properties,
    // so continue to use persisted tun object.
    bool use_persisted_tun() const { return use_persisted_tun_; }

    // Return true if new tun properties should be persisted.
    bool should_persist() const { return copt && !use_persisted_tun_; }

    // Return true if tun socket/handle should be retained.
    bool retain() const { return copt || use_persisted_tun_; }

    // Return current tun properties string.
    std::string options() const { return copt->to_string(); }

  private:
    typename TunPersist::Ptr tun_persist;
    TunBuilderCapture::Ptr copt;
    bool use_persisted_tun_;
  };

}

#endif
