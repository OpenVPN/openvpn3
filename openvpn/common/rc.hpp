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

  class RC;

  void intrusive_ptr_add_ref(RC *p);
  void intrusive_ptr_release(RC *p);

  class RC : boost::noncopyable
  {
  public:
    RC() : refcount_(0) {}
    virtual ~RC() {}
  private:
    friend void intrusive_ptr_add_ref(RC* p);
    friend void intrusive_ptr_release(RC* p);
    boost::detail::atomic_count refcount_;
  };

  inline void intrusive_ptr_add_ref(RC *p)
  {
    ++p->refcount_;
  }

  inline void intrusive_ptr_release(RC *p)
  {
    if (--p->refcount_ == 0)
      delete p;
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_RC_H
