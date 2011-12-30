#ifndef OPENVPN_COMMON_BIDIR_H
#define OPENVPN_COMMON_BIDIR_H

#include <openvpn/common/rc.hpp>

namespace openvpn {

  template <typename PARENT, typename CHILD>
  struct BidirObjBase : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<CHILD> Ptr;

    struct ConfigBase : public RC<thread_unsafe_refcount>
    {
      typedef boost::intrusive_ptr<ConfigBase> Ptr;

      virtual BidirObjBase::Ptr create_new(PARENT&) = 0;
    };
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_BIDIR_H
