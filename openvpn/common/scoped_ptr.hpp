#ifndef OPENVPN_COMMON_SCOPED_PTR_H
#define OPENVPN_COMMON_SCOPED_PTR_H

#include <algorithm>

#include <boost/assert.hpp>
#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>

namespace openvpn {

  // like boost::scoped_ptr but has release, reset methods and default constructor usage
  template <typename T>
  class ScopedPtr : boost::noncopyable
  {
  public:
    explicit ScopedPtr(T* p = 0)
      : px(p) {}

    void reset(T* p = 0)
    {
      if (px)
	delete px;
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

    ~ScopedPtr() {
      if (px)
	delete px;
    }

  private:
    T* px;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_SCOPED_PTR_H
