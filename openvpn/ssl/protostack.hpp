#ifndef OPENVPN_SSL_PROTOSTACK_H
#define OPENVPN_SSL_PROTOSTACK_H

#include <deque>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/usecount.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/reliable/relrecv.hpp>
#include <openvpn/reliable/relsend.hpp>
#include <openvpn/reliable/relack.hpp>
#include <openvpn/frame/frame.hpp>

namespace openvpn {

  // PACKET type must define the following methods:
  //
  // Default constructor:
  //   PACKET()
  //
  // Constructor for BufferPtr:
  //   explicit PACKET(const BufferPtr& buf)
  //
  // Test if defined:
  //   operator bool() const
  //
  // Return true if packet is raw, or false if packet is SSL ciphertext:
  //   bool is_raw() const
  //
  // Reset back to post-default-constructor state:
  //   void reset()
  //
  // Return internal BufferPtr:
  //   const BufferPtr& buffer_ptr() const
  //
  // Call frame.prepare on internal buffer:
  //   void frame_prepare(const Frame& frame, const unsigned int context)

  template <typename SSL_CONTEXT, typename PACKET>
  class ProtoStackBase
  {
  public:
    typedef SSL_CONTEXT SSLContext;
    typedef reliable::id_t id_t;
    typedef ReliableSendTemplate<PACKET> ReliableSend;
    typedef ReliableRecvTemplate<PACKET> ReliableRecv;

    OPENVPN_SIMPLE_EXCEPTION(proto_stack_invalidated);

    ProtoStackBase(SSLContext& ctx,
		   const FramePtr& frame,
		   const id_t span,
		   const size_t max_ack_list)
      : ssl_(ctx.ssl()),
	frame_(frame),
	rel_recv(span),
	rel_send(span),
	xmit_acks(max_ack_list),
	up_stack_reentry_level(0),
	invalidate(false),
	next_retransmit_(Time::infinite())
    {
    }

    // Start SSL handshake on underlying SSL connection object
    void start_handshake()
    {
      test_invalidated();
      ssl_->start_handshake();
    }

    // Incoming ciphertext packet arriving from network
    void net_recv(const Time now, PACKET& pkt)
    {
      test_invalidated();
      up_stack(now, pkt);
      update_retransmit(now);
    }

    // Outgoing application-level cleartext packet ready to send
    // (will be encrypted via SSL)
    void app_send(const Time now, BufferPtr& buf)
    {
      app_write_queue.push_back(buf);
    }

    // Outgoing raw packet ready to send (will NOT be encrypted
    // via SSL, but will still be encapsulated and tracked
    // via reliability layer).
    void raw_send(const Time now, const PACKET& pkt)
    {
      raw_write_queue.push_back(pkt);
    }

    // Write any pending data to network.  Should be called
    // as a final step after one or more net_recv, app_send,
    // or raw_send calls.
    void flush(const Time now)
    {
      test_invalidated();
      if (!up_stack_reentry_level)
	{
	  down_stack_raw(now);
	  down_stack_app(now);
	  update_retransmit(now);
	}
    }

    // Send pending ACKs back to sender for packets already received
    void send_pending_acks(const Time now)
    {
      test_invalidated();
      while (!xmit_acks.empty())
	{
	  ack_send_buf.frame_prepare(*frame_, Frame::WRITE_ACK_STANDALONE);

	  // encapsulate standalone ACK
	  generate_ack(now, ack_send_buf, xmit_acks);

	  // transmit it
	  net_send(now, ack_send_buf);
	}
    }

    // Send any pending retransmissions
    void retransmit(const Time now)
    {
      test_invalidated();
      for (id_t i = rel_send.head_id(); i < rel_send.tail_id(); ++i)
	{
	  typename ReliableSend::Message& m = rel_send.ref_by_id(i);
	  if (m.ready_retransmit(now))
	    {
	      net_send(now, m.packet);
	      m.reset_retransmit(now);
	    }
	}
      update_retransmit(now);
    }

    // When should we next call retransmit()
    Time next_retransmit() const { return next_retransmit_; }

    // Was session invalidated by an exception?
    bool invalidated() const { return invalidate; }

    virtual ~ProtoStackBase() {}

  private:
    // VIRTUAL METHODS -- derived class must define these virtual methods

    // Encapsulate packet, use id as sequence number, xmit_acks as ACKs
    // in reply to sender (if non-NULL), any exceptions thrown will
    // invalidate session, i.e. this object can no longer be used.
    virtual void encapsulate(const Time now, id_t id, PACKET& pkt, ReliableAck& xmit_acks) = 0;

    // Un-encapsulate packet, method should return sequence number,
    // or PacketID::UNDEF if packet should be dropped.
    // Any ACKs received for messages previously sent should be marked in
    // rel_send, which can be accomplished by calling ReliableAck::ack().
    // Exceptions may be thrown here and they will be passed up to
    // caller of net_recv and will not invalidate the session, however
    // the packet will be dropped.
    virtual id_t decapsulate(const Time now, PACKET& pkt, ReliableSend& rel_send) = 0;

    // Generate a standalone ACK message in buf (PACKET will be initialized by frame_prepare()).
    virtual void generate_ack(const Time now, PACKET& pkt, ReliableAck& xmit_acks) = 0;

    // Transmit encapsulated ciphertext packet to peer.  Method may not modify
    // or take ownership of net_buf underlying data unless it copies it.
    virtual void net_send(const Time now, const PACKET& net_pkt) = 0;

    // Pass cleartext data up to application.  Method may take ownership
    // of to_app_buf by making private copy of BufferPtr then calling
    // reset on to_app_buf.
    virtual void app_recv(const Time now, BufferPtr& to_app_buf) = 0;

    // Pass raw data up to application.  A packet is considered to be raw
    // if is_raw() method returns true.
    virtual void raw_recv(const Time now, PACKET& raw_pkt) = 0;

    // END of VIRTUAL METHODS


    // app data -> SSL -> protocol encapsulation -> reliability layer -> network
    void down_stack_app(const Time now)
    {
      // push app-layer cleartext through SSL object
      while (!app_write_queue.empty())
	{
	  BufferPtr& buf = app_write_queue.front();
	  try {
	    const ssize_t size = ssl_->write_cleartext_unbuffered(buf->data(), buf->size());
	    if (size == SSLContext::SSL::SHOULD_RETRY)
	      break;
	  }
	  catch (...)
	    {
	      invalidate = true;
	      throw;
	    }
	  app_write_queue.pop_front();
	}

      // encapsulate SSL ciphertext packets
      while (ssl_->read_ciphertext_ready() && rel_send.ready())
	{
	  typename ReliableSend::Message& m = rel_send.send(now);
	  m.packet = PACKET(ssl_->read_ciphertext());

	  // encapsulate packet
	  try {
	    encapsulate(now, m.id(), m.packet, xmit_acks);
	  }
	  catch (...)
	    {
	      invalidate = true;
	      throw;
	    }

	  // transmit it
	  net_send(now, m.packet);
	}
    }

    // raw app data -> protocol encapsulation -> reliability layer -> network
    void down_stack_raw(const Time now)
    {
      while (!raw_write_queue.empty() && rel_send.ready())
	{
	  typename ReliableSend::Message& m = rel_send.send(now);
	  m.packet = raw_write_queue.front();
	  raw_write_queue.pop_front();

	  // encapsulate packet
	  try {
	    encapsulate(now, m.id(), m.packet, xmit_acks);
	  }
	  catch (...)
	    {
	      invalidate = true;
	      throw;
	    }

	  // transmit it
	  net_send(now, m.packet);
	}
    }

    // network -> reliability layer -> protocol decapsulation -> SSL -> app
    void up_stack(const Time now, PACKET& recv)
    {
      UseCount use_count(up_stack_reentry_level);

      {
	// decapsulate packet
	const id_t id = decapsulate(now, recv, rel_send);
	if (id != PacketID::UNDEF)
	  {
	    const bool should_ack = rel_recv.receive(recv, id);
	    if (should_ack)
	      xmit_acks.push_back(id);
	  }
      }

      // is sequenced receive packet available?
      bool wrote_ciphertext = false; // true if we wrote received ciphertext into SSL object
      while (rel_recv.ready())
	{
	  typename ReliableRecv::Message& m = rel_recv.next_sequenced();
	  if (m.packet.is_raw())
	    raw_recv(now, m.packet);
	  else
	    {
	      ssl_->write_ciphertext(m.packet.buffer_ptr());
	      wrote_ciphertext = true;
	    }
	  rel_recv.advance();
	}

      // read cleartext data from SSL object
      if (wrote_ciphertext)
	while (true)
	  {
	    ssize_t size;
	    if (!to_app_buf)
	      to_app_buf.reset(new BufferAllocated());
	    frame_->prepare(Frame::READ_SSL_CLEARTEXT, *to_app_buf);
	    try {
	      size = ssl_->read_cleartext(to_app_buf->data(), to_app_buf->max_size());
	    }
	    catch (...)
	      {
		// SSL fatal errors will invalidate the session
		invalidate = true;
		throw;
	      }
	    if (size == SSLContext::SSL::SHOULD_RETRY)
	      break;
	    to_app_buf->set_size(size);

	    // pass cleartext data to app
	    app_recv(now, to_app_buf);
	  }
    }

    void test_invalidated() const
    {
      if (invalidate)
	throw proto_stack_invalidated();
    }

    void update_retransmit(const Time now)
    {
      const Time::Duration d = rel_send.until_retransmit(now);
      if (d.is_infinite())
	next_retransmit_ = Time::infinite();
      else
	next_retransmit_ = now + d;
    }

    typename SSLContext::SSLPtr ssl_;
    FramePtr frame_;

    ReliableRecv rel_recv;
    ReliableSend rel_send;
    ReliableAck xmit_acks;

    int up_stack_reentry_level;
    bool invalidate;

    Time next_retransmit_;

    BufferPtr to_app_buf; // cleartext data decrypted by SSL that is to be passed to app via app_recv method
    PACKET ack_send_buf;  // only used for standalone ACKs to be sent to peer

    std::deque<BufferPtr> app_write_queue;
    std::deque<PACKET> raw_write_queue;
  };

} // namespace openvpn

#endif // OPENVPN_SSL_PROTOSTACK_H
