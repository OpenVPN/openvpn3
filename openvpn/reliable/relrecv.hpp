#ifndef OPENVPN_RELIABLE_RELRECV_H
#define OPENVPN_RELIABLE_RELRECV_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/msgwin.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/reliable/relcommon.hpp>

namespace openvpn {

  class ReliableRecv
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(rel_next_sequenced_not_ready);

    typedef ReliableMessageBase::id_t id_t;

    class Message : public ReliableMessageBase
    {
      friend class ReliableRecv;
    };

    ReliableRecv() {}
    ReliableRecv(const id_t span) { init(span); }

    void init(const id_t span)
    {
      window_.init(1, span);
    }

    // Call with unsequenced packet off of the wire.
    // Will return true if ACK for this packet ID
    // should be returned to sender.
    bool receive(BufferPtr& buffer, const id_t id)
    {
      if (window_.in_window(id))
	{
	  Message& m = window_.ref_by_id(id);
	  m.id_ = id;
	  m.buffer = buffer;
	  return true;
	}
      else
	return window_.pre_window(id);
    }

    // Return true if next_sequenced() is ready to return next buffer
    bool ready() const { return window_.head_defined(); }

    // Return next buffer in sequence.
    // Requires that ready() returns true.
    Message& next_sequenced()
    {
      return window_.ref_head();
    }

    // Call after buffer returned by receive is ready to
    // be disposed of.
    void advance()
    {
      window_.rm_head_nocheck();
    }

  private:
    MessageWindow<Message, id_t> window_;
  };

} // namespace openvpn

#endif // OPENVPN_RELIABLE_RELRECV_H
