//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
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

  // Reference count base class for objects tracked by boost::intrusive_ptr.
  // Disallows copying and assignment.
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

  // Like RC, but allows object to be copied and assigned.
  template <typename RCImpl> // RCImpl = thread_safe_refcount or thread_unsafe_refcount
  class RCCopyable
  {
  public:
    RCCopyable() : refcount_(0) {}
    RCCopyable(const RCCopyable&) : refcount_(0) {}
    RCCopyable& operator=(const RCCopyable&) { return *this; }
    virtual ~RCCopyable() {}
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
