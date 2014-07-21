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

// A scoped pointer class similar to boost::scoped_ptr.

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

    T* operator()() const
    {
      return px;
    }

    T** ref()
    {
      return &px;
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
