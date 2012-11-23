//
//  relcommon.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Common reliability layer classes

#ifndef OPENVPN_RELIABLE_RELCOMMON_H
#define OPENVPN_RELIABLE_RELCOMMON_H

#include <openvpn/crypto/packet_id.hpp>

namespace openvpn {

  namespace reliable {
    typedef PacketID::id_t id_t;    
  }

  template <typename PACKET>
  class ReliableMessageBase
  {
  public:
    typedef reliable::id_t id_t;

    ReliableMessageBase() : id_(0), erased_(false) {}
    bool defined() const { return bool(packet); }
    bool erased() const { return erased_; }

    void erase()
    {
      id_ = id_t(0);
      packet.reset();
      erased_ = true;
    }

    id_t id() const { return id_; }

    PACKET packet;

  protected:
    id_t id_;
    bool erased_;
  };

} // namespace openvpn

#endif // OPENVPN_RELIABLE_RELCOMMON_H
