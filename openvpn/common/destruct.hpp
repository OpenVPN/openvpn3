//
//  destruct.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_DESTRUCT_H
#define OPENVPN_COMMON_DESTRUCT_H

#include <openvpn/common/rc.hpp>

// used for general-purpose cleanup

namespace openvpn {

  struct DestructorBase : public RC<thread_unsafe_refcount>
  {
    typedef boost::intrusive_ptr<DestructorBase> Ptr;
    virtual void destroy() = 0;
    virtual ~DestructorBase() {}
  };

}

#endif
