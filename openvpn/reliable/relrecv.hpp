#ifndef OPENVPN_RELIABLE_RELRECV_H
#define OPENVPN_RELIABLE_RELRECV_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/msgwin.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/crypto/packet_id.hpp>

namespace openvpn {

  class ReliableRecv
  {
  public:
    typedef PacketID::id_t id_t;

    OPENVPN_SIMPLE_EXCEPTION(next_sequenced_not_ready);

    struct Message
    {
    public:
      Message() : id(0) {}
      bool defined() const { return bool(buffer); }
      void erase() { buffer.reset(); }

      id_t id;
      BufferPtr buffer;
    };

    // Call with unsequenced packet off of the wire.
    // Will return true if ACK for this packet ID
    // should be returned to sender.
    bool receive(BufferPtr& buffer, const id_t id)
    {
      if (window.in_window(id))
	{
	  Message& m = window.ref_by_id(id);
	  m.id = id;
	  m.buffer = buffer;
	  return true;
	}
      else
	return window.pre_window(id);
    }

    // Return true if next_sequenced() is ready to return next buffer
    bool ready() const { return window.head_defined(); }

    // Return next buffer in sequence.  Requires that ready() returns true.
    Message next_sequenced()
    {
      if (ready())
	{
	  Message ret = window.ref_head();
	  window.rm_head_nocheck();
	  return ret;
	}
      else
	throw next_sequenced_not_ready();
    }

  private:
    MessageWindow<Message, id_t> window;
  };

} // namespace openvpn

#endif // OPENVPN_RELIABLE_RELRECV_H
