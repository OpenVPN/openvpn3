#ifndef OPENVPN_APPLECRYPTO_CF_CF_H
#define OPENVPN_APPLECRYPTO_CF_CF_H

#include <CoreFoundation/CFBase.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {

  template <typename T>
  class CFWrap
  {
  public:
    CFWrap() : obj_(NULL) {}

    explicit CFWrap(T obj, bool borrow=false)
       : obj_(NULL)
    {
      if (obj && borrow)
	CFRetain(obj);
      obj_ = obj;
    }

    CFWrap(const CFWrap& other)
    {
      obj_ = other.obj_;
      if (obj_)
	CFRetain(obj_);
    }

    CFWrap& operator=(const CFWrap& other)
    {
      if (other.obj_)
	CFRetain(other.obj_);
      if (obj_)
	CFRelease(obj_);
      obj_ = other.obj_;
      return *this;
    }

    void reset(T obj, bool borrow=false)
    {
      if (obj && borrow)
	CFRetain(obj);
      if (obj_)
	CFRelease(obj_);
      obj_ = obj;
    }

    bool defined() const { return obj_ != NULL; }

    T operator()() const { return obj_; }

    void show() const
    {
      if (obj_)
	CFShow(obj_);
    }

    virtual ~CFWrap()
    {
      if (obj_)
	CFRelease(obj_);
    }

  private:
    CFWrap& operator=(T obj); // prevent use because no way to pass borrow parameter

    T obj_;
  };

} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_CF_CF_H
