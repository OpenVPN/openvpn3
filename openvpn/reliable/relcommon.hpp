#ifndef OPENVPN_RELIABLE_RELCOMMON_H
#define OPENVPN_RELIABLE_RELCOMMON_H

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/crypto/packet_id.hpp>

namespace openvpn {

  class ReliableMessageBase
  {
  public:
    typedef PacketID::id_t id_t;

    ReliableMessageBase() : id_(0), erased_(false) {}
    bool defined() const { return bool(buffer); }
    bool erased() const { return erased_; }

    void erase()
    {
      id_ = id_t(0);
      buffer.reset();
      erased_ = true;
    }

    id_t id() const { return id_; }

    BufferPtr buffer;

  protected:
    id_t id_;
    bool erased_;
  };

} // namespace openvpn

#endif // OPENVPN_RELIABLE_RELCOMMON_H
