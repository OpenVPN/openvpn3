//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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
// We use tend to use boost::intrusive_ptr rather than the other boost/std
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
//   typedef RCPtr<Foo> Ptr;
// };
//
// This allows a smart-pointer to Foo to be referred to
// as Foo::Ptr

#ifndef OPENVPN_COMMON_RC_H
#define OPENVPN_COMMON_RC_H

#include <atomic>

#include <boost/intrusive_ptr.hpp>

#include <openvpn/common/olong.hpp>

#ifdef OPENVPN_RC_DEBUG
#include <iostream>
#include <openvpn/common/demangle.hpp>
#endif

namespace openvpn {

  // The smart pointer
  template<typename T>
  using RCPtr = boost::intrusive_ptr<T>;

  class thread_unsafe_refcount
  {
    thread_unsafe_refcount(const thread_unsafe_refcount&) = delete;
    thread_unsafe_refcount& operator=(const thread_unsafe_refcount&) = delete;

  public:
    thread_unsafe_refcount() noexcept
      : rc(olong(0))
    {
    }

    void operator++()
    {
      ++rc;
    }

    olong operator--()
    {
      return --rc;
    }

    bool inc_if_nonzero()
    {
      if (rc)
	{
	  ++rc;
	  return true;
	}
      else
	return false;
    }

    olong use_count() const
    {
      return rc;
    }

  private:
    olong rc;
  };

  class thread_safe_refcount
  {
    thread_safe_refcount(const thread_safe_refcount&) = delete;
    thread_safe_refcount& operator=(const thread_safe_refcount&) = delete;

  public:
    thread_safe_refcount() noexcept
      : rc(olong(0))
    {
    }

    void operator++()
    {
      rc.fetch_add(1, std::memory_order_relaxed);
    }

    olong operator--()
    {
      // http://www.boost.org/doc/libs/1_55_0/doc/html/atomic/usage_examples.html
      const olong ret = rc.fetch_sub(1, std::memory_order_release) - 1;
      if (ret == 0)
	std::atomic_thread_fence(std::memory_order_acquire);
      return ret;
    }

    // If refcount is 0, do nothing and return false.
    // If refcount != 0, increment it and return true.
    bool inc_if_nonzero()
    {
      olong previous = rc.load(std::memory_order_relaxed);
      while (true)
	{
	  if (!previous)
	    break;
	  if (rc.compare_exchange_weak(previous, previous + 1, std::memory_order_relaxed))
	    break;
	}
      return previous > 0;
    }

    olong use_count() const
    {
      return rc.load(std::memory_order_relaxed);
    }

  private:
    std::atomic<olong> rc;
  };

  // Reference count base class for objects tracked by boost::intrusive_ptr.
  // Disallows copying and assignment.
  template <typename RCImpl> // RCImpl = thread_safe_refcount or thread_unsafe_refcount
  class RC
  {
    RC(const RC&) = delete;
    RC& operator=(const RC&) = delete;

  public:
    RC() noexcept {}
    virtual ~RC() {}
  private:
    template <typename R> friend void intrusive_ptr_add_ref(R* p) noexcept;
    template <typename R> friend void intrusive_ptr_release(R* p) noexcept;
    RCImpl refcount_;
  };

  // Like RC, but allows object to be copied and assigned.
  template <typename RCImpl> // RCImpl = thread_safe_refcount or thread_unsafe_refcount
  class RCCopyable
  {
  public:
    RCCopyable() noexcept {}
    RCCopyable(const RCCopyable&) noexcept {}
    RCCopyable& operator=(const RCCopyable&) noexcept { return *this; }
    virtual ~RCCopyable() {}
  private:
    template <typename R> friend void intrusive_ptr_add_ref(R* p) noexcept;
    template <typename R> friend void intrusive_ptr_release(R* p) noexcept;
    RCImpl refcount_;
  };

  // Like RC, but also allows weak pointers
  template <typename RCImpl> // RCImpl = thread_safe_refcount or thread_unsafe_refcount
  class RCWeak
  {
    RCWeak(const RCWeak&) = delete;
    RCWeak& operator=(const RCWeak&) = delete;

    template<typename T>
    friend class RCWeakPtr;

    // For weak-referenceable objects, we must detach the
    // refcount from the object and place it in Controller.
    struct Controller : public RC<RCImpl>
    {
      typedef RCPtr<Controller> Ptr;

      Controller(RCWeak* parent_arg) noexcept
	: parent(parent_arg)
      {
      }

      olong use_count() const
      {
	return rc.use_count();
      }

      template <typename PTR>
      PTR lock()
      {
	if (rc.inc_if_nonzero())
	  return PTR(static_cast<typename PTR::element_type*>(parent), false);
	else
	  return PTR();
      }

      RCWeak *const parent; // dangles after rc == 0
      RCImpl rc;
    };

    struct ControllerRef
    {
      ControllerRef(RCWeak* parent) noexcept
        : controller(new Controller(parent))
      {
      }

      void operator++()
      {
	++controller->rc;
      }

      olong operator--()
      {
	return --controller->rc;
      }

      typename Controller::Ptr controller;
    };

  public:
    RCWeak() noexcept
      : refcount_(this)
    {
    }

    virtual ~RCWeak()
    {
    }

  private:
    template <typename R> friend void intrusive_ptr_add_ref(R* p) noexcept;
    template <typename R> friend void intrusive_ptr_release(R* p) noexcept;
    ControllerRef refcount_;
  };

  template <typename T>
  class RCWeakPtr
  {
    typedef RCPtr<T> Strong;

  public:
    typedef T element_type;

    RCWeakPtr() noexcept {}

    RCWeakPtr(const Strong& p) noexcept
    {
      if (p)
	controller = p->refcount_.controller;
    }

    RCWeakPtr(T* p) noexcept
    {
      if (p)
	controller = p->refcount_.controller;
    }

    void reset(const Strong& p) noexcept
    {
      if (p)
	controller = p->refcount_.controller;
      else
	controller.reset();
    }

    void reset(T* p) noexcept
    {
      if (p)
	controller = p->refcount_.controller;
      else
	controller.reset();
    }

    void reset() noexcept
    {
      controller.reset();
    }

    void swap(RCWeakPtr& other) noexcept
    {
      controller.swap(other.controller);
    }

    olong use_count() const
    {
      if (controller)
	return controller->use_count();
      else
	return 0;
    }

    bool expired() const
    {
      return use_count() == 0;
    }

    Strong lock() const
    {
      if (controller)
	return controller->template lock<Strong>();
      else
	return Strong();
    }

  private:
    typename T::Controller::Ptr controller;
  };

#if !defined(OPENVPN_RC_USERDEF)

  template <typename R>
  inline void intrusive_ptr_add_ref(R *p) noexcept
  {
#ifdef OPENVPN_RC_DEBUG
    std::cout << "ADD REF " << cxx_demangle(typeid(p).name()) << std::endl;
#endif
    ++p->refcount_;
  }

  template <typename R>
  inline void intrusive_ptr_release(R *p) noexcept
  {
    if (--p->refcount_ == 0)
      {
#ifdef OPENVPN_RC_DEBUG
	std::cout << "DEL OBJ " << cxx_demangle(typeid(p).name()) << std::endl;
#endif
	delete p;
      }
    else
      {
#ifdef OPENVPN_RC_DEBUG
	std::cout << "REL REF " << cxx_demangle(typeid(p).name()) << std::endl;
#endif
      }
  }

#endif

} // namespace openvpn

#endif // OPENVPN_COMMON_RC_H
