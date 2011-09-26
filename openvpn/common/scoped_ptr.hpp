#ifndef OPENVPN_COMMON_SCOPED_PTR_H
#define OPENVPN_COMMON_SCOPED_PTR_H

#include <boost/assert.hpp>
#include <boost/noncopyable.hpp>

namespace openvpn {

  // like boost::scoped_ptr but has release method
  template <typename T>
  class ScopedPtr : boost::noncopyable
  {
  public:
    explicit ScopedPtr(T* p)
      : px(p) {}

    T* release() {
      T* ret = px;
      px = NULL;
      return ret;
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

#endif //  OPENVPN_COMMON_SCOPED_PTR_H
