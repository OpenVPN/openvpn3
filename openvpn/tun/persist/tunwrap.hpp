//
//  tunwrap.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_TUN_PERSIST_TUNWRAP_H
#define OPENVPN_TUN_PERSIST_TUNWRAP_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/destruct.hpp>

namespace openvpn {

  // TunWrapTemplate is used client-side to store the underlying tun
  // interface fd/handle.  SCOPED_OBJ is generally a ScopedFD (unix) or a
  // ScopedHANDLE (Windows).  It can also be a ScopedAsioStream.
  template <typename SCOPED_OBJ>
  class TunWrapTemplate : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<TunWrapTemplate> Ptr;

    TunWrapTemplate(const bool retain_obj)
      : retain_obj_(retain_obj)
    {
    }

    virtual ~TunWrapTemplate()
    {
      close();
    }

    bool obj_defined() const
    {
      return obj_.defined();
    }

    // Current persisted tun fd/handle
    typename SCOPED_OBJ::base_type obj() const
    {
      return obj_();
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

    void close()
    {
      if (retain_obj_)
	obj_.release();
      else
	{
	  close_destructor();
	  obj_.close();
	}
    }

    void save_replace_sock(const typename SCOPED_OBJ::base_type obj)
    {
      if (retain_obj_)
	obj_.replace(obj);
      else
	obj_.reset(obj);
    }

  private:
    const bool retain_obj_;
    DestructorBase::Ptr destruct_;
    SCOPED_OBJ obj_;
  };

}
#endif
