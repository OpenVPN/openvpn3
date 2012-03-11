#ifndef OPENVPN_RANDOM_RANDBASE_H
#define OPENVPN_RANDOM_RANDBASE_H

#include <openvpn/common/rc.hpp>

namespace openvpn {
  class RandomBase : public RC<thread_unsafe_refcount>
  {
  public:
    OPENVPN_EXCEPTION(rand_error);

    typedef boost::intrusive_ptr<RandomBase> Ptr;

    virtual void rand_bytes(unsigned char *buf, const size_t size) = 0;
    virtual const char *name() const = 0;
  };
}
#endif
