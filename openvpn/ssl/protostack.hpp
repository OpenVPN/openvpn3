#ifndef OPENVPN_SSL_PROTOSTACK_H
#define OPENVPN_SSL_PROTOSTACK_H

#include <openvpn/common/exception.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/usecount.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/time/time.hpp>
#include <openvpn/reliable/relrecv.hpp>
#include <openvpn/reliable/relsend.hpp>
#include <openvpn/reliable/relack.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/buffer/memq.hpp>

namespace openvpn {

  template <typename SSLCTX>
  class ProtoStackBase
  {
  public:
    typedef SSLCTX SSLContext;
    typedef ReliableMessageBase::id_t id_t;

    OPENVPN_SIMPLE_EXCEPTION(proto_stack_invalidated);

    ProtoStackBase(SSLContext& ctx,
		   const FramePtr& frame,
		   const id_t span)
      : ssl_(ctx.ssl()),
	frame_(frame),
	rel_recv(span),
	rel_send(span),
	up_stack_reentry_level(0),
	invalidate(false)
    {
    }

    // Incoming ciphertext packet arriving from network
    void net_recv(const Time now, BufferPtr& buf)
    {
      test_invalidated();
      up_stack(now, buf);
    }

    // Outgoing application-level cleartext packet ready to send
    void app_send(const Time now, BufferPtr& buf)
    {
      test_invalidated();
      app_write_queue.write_buf(buf);
      if (!up_stack_reentry_level)
	down_stack(now, NULL);
    }

    // Return the shortest duration for any pending retransmissions.
    // Call retransmit() at current time + returned duration.
    Time::Duration until_retransmit(const Time now)
    {
      return rel_send.until_retransmit(now);
    }

    // Send any pending retransmissions
    void retransmit(const Time now)
    {
      for (id_t i = rel_send.head_id(); i < rel_send.tail_id(); ++i)
	{
	  ReliableSend::Message& m = rel_send.ref_by_id(i);
	  if (m.ready_retransmit(now))
	    {
	      net_send(now, m.buffer);
	      m.reset_retransmit(now);
	    }
	}
    }

    // was session invalidated by an exception?
    bool invalidated() const { return invalidate; }

    virtual ~ProtoStackBase() {}

  private:
    // VIRTUAL METHODS -- derived class must define these virtual methods

    // Encapsulate buffer, use id as sequence number, xmit_acks as ACKs
    // in reply to sender (if non-NULL), any exceptions thrown will
    // invalidate session, i.e. this object can no longer be used.
    virtual void encapsulate(const Time now, id_t id, BufferPtr& buf, ReliableAck* xmit_acks) = 0;

    // Un-encapsulate buffer returning sequence number, reset recv if packet
    // should be dropped (in which case return value will be ignored).
    // Exceptions may be thrown here and they will be passed up to
    // caller of net_recv and will not invalidate the session, however
    // the packet will be dropped.
    virtual id_t decapsulate(const Time now, BufferPtr& recv) = 0;

    // Generate a standalone ACK message in buf (buf is already allocated and framed).
    virtual void generate_ack(const Time now, BufferPtr& buf, ReliableAck& xmit_acks) = 0;

    // Transmit encapsulated ciphertext buffer to peer.  Method may take ownership
    // of net_buf by making private copy then calling reset on net_buf.
    virtual void net_send(const Time now, BufferPtr& net_buf) = 0;

    // Pass cleartext data up to application.  Method may take ownership
    // of to_app_buf by making private copy then calling reset on to_app_buf.
    virtual void app_recv(const Time now, BufferPtr& to_app_buf) = 0;

    // END of VIRTUAL METHODS


    // app data -> SSL -> protocol encapsulation -> reliability layer -> network
    void down_stack(const Time now, ReliableAck* xmit_acks)
    {
      // push app-layer cleartext through SSL object
      while (!app_write_queue.empty())
	{
	  BufferPtr& buf = app_write_queue.peek();
	  try {
	    if (ssl_->write_cleartext_unbuffered(buf->data(), buf->size()) == SSLContext::SSL::SHOULD_RETRY)
	      break;
	  }
	  catch (...)
	    {
	      invalidate = true;
	      throw;
	    }
	  app_write_queue.pop();
	}

      // encapsulate SSL ciphertext packets
      while (ssl_->read_ciphertext_ready() && rel_send.ready())
	{
	  ReliableSend::Message& m = rel_send.send(now);
	  m.buffer = ssl_->read_ciphertext();

	  // encapsulate buffer
	  try {
	    encapsulate(now, m.id(), m.buffer, xmit_acks);
	  }
	  catch (...)
	    {
	      invalidate = true;
	      throw;
	    }

	  // transmit it
	  net_send(now, m.buffer);
	}

      // send standalone ACKs
      send_standalone_acks(now, xmit_acks);
    }

    void send_standalone_acks(const Time now, ReliableAck* xmit_acks)
    {
      if (xmit_acks)
	while (!xmit_acks->empty())
	  {
	    if (!ack_send_buf)
	      ack_send_buf.reset(new BufferAllocated());
	    frame_->prepare(Frame::WRITE_ACK_STANDALONE, *ack_send_buf);

	    // encapsulate standalone ACK
	    generate_ack(now, ack_send_buf, *xmit_acks);

	    // transmit it
	    net_send(now, ack_send_buf);
	  }
    }

    // network -> reliability layer -> protocol decapsulation -> SSL -> app
    void up_stack(const Time now, BufferPtr& recv)
    {
      UseCount use_count(up_stack_reentry_level);
      ReliableAck xmit_acks;

      {
	// decapsulate buffer
	const id_t id = decapsulate(now, recv);

	if (recv)
	  {
	    const bool should_ack = rel_recv.receive(recv, id);
	    if (should_ack)
	      xmit_acks.push_back(id);
	  }
      }

      // is sequenced receive packet available?
      while (rel_recv.ready())
	{
	  ReliableRecv::Message& m = rel_recv.next_sequenced();
	  ssl_->write_ciphertext(m.buffer);
	  rel_recv.advance();
	}

      // read cleartext data from SSL object
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
	  try {
	    app_recv(now, to_app_buf);
	  }
	  catch (...)
	    {
	      // even if exception thrown, still ACK packet received
	      send_standalone_acks(now, &xmit_acks);
	      throw;
	    }
	}

      // handle app writes made from app_recv as well as sending ACK replies
      down_stack(now, &xmit_acks);
    }

    void test_invalidated() const
    {
      if (invalidate)
	throw proto_stack_invalidated();
    }

    typename SSLContext::SSLPtr ssl_;
    FramePtr frame_;

    ReliableRecv rel_recv;
    ReliableSend rel_send;

    int up_stack_reentry_level;
    bool invalidate;

    BufferPtr to_app_buf;   // cleartext data decrypted by SSL that is to be passed to app via app_recv method
    BufferPtr ack_send_buf; // only used for standalone ACKs to be sent to peer

    MemQBase app_write_queue;
  };

} // namespace openvpn

#endif // OPENVPN_SSL_PROTOSTACK_H
