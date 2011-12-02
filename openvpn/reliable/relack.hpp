#ifndef OPENVPN_RELIABLE_RELACK_H
#define OPENVPN_RELIABLE_RELACK_H

#include <deque>
#include <algorithm>
#include <limits>

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/crypto/packet_id.hpp>
#include <openvpn/reliable/relcommon.hpp>
#include <openvpn/reliable/relsend.hpp>

namespace openvpn {

  class ReliableAck
  {
  public:
    typedef ReliableMessageBase::id_t id_t;

    ReliableAck(const size_t max_ack_list)
      : max_ack_list_(max_ack_list ? max_ack_list : std::numeric_limits<size_t>::max()) {}

    size_t size() const        { return data.size(); }
    bool empty() const         { return data.empty(); }
    void push_back(id_t value) { data.push_back(value); }
    id_t front() const         { return data.front(); }
    void pop_front()           { data.pop_front(); }

    // called to read incoming ACKs from buf and mark them as ACKed in rel_send
    static void ack(ReliableSend& rel_send, Buffer& buf)
    {
      const size_t len = buf.pop_front();
      for (size_t i = 0; i < len; ++i)
	{
	  const id_t id = PacketID::read_id(buf);
	  rel_send.ack(id);
	}
    }

    // copy ACKs from buffer to self
    void read(Buffer& buf)
    {
      const size_t len = buf.pop_front();
      for (size_t i = 0; i < len; ++i)
	{
	  const id_t id = PacketID::read_id(buf);
	  data.push_back(id);
	}
    }

    // called to write outgoing ACKs to buf
    void prepend(Buffer& buf)
    {
      const size_t len = std::min(data.size(), max_ack_list_);
      for (size_t i = len; i > 0; --i)
	{
	  PacketID::prepend_id(buf, data[i-1]);
	}
      buf.push_front((unsigned char)len);
      data.erase (data.begin(), data.begin()+len);
    }

  private:
    size_t max_ack_list_; // Maximum number of ACKs placed in a single message by prepend_acklist()
    std::deque<id_t> data;
  };

} // namespace openvpn

#endif // OPENVPN_RELIABLE_RELACK_H
