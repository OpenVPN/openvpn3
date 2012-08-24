//
//  scoped_ptr.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_SCOPED_PTR_H
#define OPENVPN_COMMON_SCOPED_PTR_H

#include <algorithm>

#include <boost/assert.hpp>
#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>

namespace openvpn {

  // default delete method for ScopedPtr
  template <typename T>
  class PtrFree {
  public:
    static void del(T* p)
    {
      delete p;
    }
  };

  // array delete method for ScopedPtr
  template <typename T>
  class PtrArrayFree {
  public:
    static void del(T* p)
    {
      delete [] p;
    }
  };

  // Similar to boost::scoped_ptr but has release, reset methods,
  // and default constructor usage.  Also allows definition of
  // alternative delete methods via second argument.
  template <typename T, template <typename TF> class F = PtrFree>
  class ScopedPtr : boost::noncopyable
  {
  public:
    explicit ScopedPtr(T* p = 0)
      : px(p) {}

    bool defined() const { return px != 0; }

    void reset(T* p = 0)
    {
      if (px)
	del(px);
      px = p;
    }

    T* release()
    {
      T* ret = px;
      px = NULL;
      return ret;
    }

    void swap(ScopedPtr& other)
    {
      std::swap(px, other.px);
    }

    T& operator*() const
    {
      BOOST_ASSERT( px != 0 );
      return *px;
    }

    T* operator->() const
    {
      BOOST_ASSERT( px != 0 );
      return px;
    }

    T* get() const
    {
      return px;
    }

    ~ScopedPtr()
    {
      if (px)
	del(px);
    }

    static void del(T* p)
    {
      F<T>::del(p);
    }

  protected:
    T* px;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_SCOPED_PTR_H
