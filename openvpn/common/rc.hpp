//
//  rc.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// A basic reference-counting garbage collection scheme based on
// boost::intrusive_ptr.  Simply inherit from RC to create an
// object that can be tracked with an intrusive_ptr.
//
// We use tend to use boost::intrusive_ptr rather than the other boost
// smart pointer classes because it is more efficient to have the reference
// count itself baked into the object being tracked.  The downside
// of boost::intrusive_ptr is that it cannot be used for weak references.
// Another downside of reference counting in general is that it doesn't handle
// cycles, so be sure to manually break any cycles that might arise
// before the object chain is considered for garbage collection.
//
// When using the RC template class, it is necessary to specify whether
// the reference count should be thread safe or unsafe, i.e.:
//
// class Foo : public RC<thread_safe_refcount> {}
//   or
// class Bar : public RC<thread_unsafe_refcount> {}
//
// Thread-safe reference counting can be significantly more expensive
// on SMP machines because the bus must be locked before the reference
// count can be incremented/decremented.  Therefore thread-safe reference
// counting should only be used for objects that have visibility across
// multiple threads.
//
// For clarity, any object that inherits from RC should also declare a Ptr
// typedef that defines the smart pointer type that should be used to track
// the object, e.g.:
//
// class Foo : public RC<thread_unsafe_refcount> {
// public:
//   typedef boost::intrusive_ptr<Foo> Ptr;
// };
//
// This allows a smart-pointer to Foo to be referred to
// as Foo::Ptr

#ifndef OPENVPN_COMMON_RC_H
#define OPENVPN_COMMON_RC_H

#include <boost/noncopyable.hpp>
#include <boost/intrusive_ptr.hpp>

#include <boost/smart_ptr/detail/atomic_count.hpp>

namespace openvpn {

  typedef boost::detail::atomic_count thread_safe_refcount;
  typedef long thread_unsafe_refcount;

  template <typename RCImpl> // RCImpl = thread_safe_refcount or thread_unsafe_refcount
  class RC : boost::noncopyable
  {
  public:
    RC() : refcount_(0) {}
    virtual ~RC() {}
  private:
    template <typename R> friend void intrusive_ptr_add_ref(R* p);
    template <typename R> friend void intrusive_ptr_release(R* p);
    RCImpl refcount_;
  };

  template <typename R>
  inline void intrusive_ptr_add_ref(R *p)
  {
    ++p->refcount_;
  }

  template <typename R>
  inline void intrusive_ptr_release(R *p)
  {
    if (--p->refcount_ == 0)
      delete p;
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_RC_H
