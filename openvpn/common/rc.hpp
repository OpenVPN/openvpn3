/*
 * A simple reference-counting garbage collection scheme that works
 * with boost::intrusive_ptr.  Simply inherit from RC to create an
 * object that can be tracked with an intrusive_ptr.
 */

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
