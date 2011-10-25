#ifndef OPENVPN_FRAME_FRAME
#define OPENVPN_FRAME_FRAME

#include <boost/intrusive_ptr.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

  class Frame : public RC<thread_unsafe_refcount>
  {
  public:
    // Frame context types -- we maintain a Context object for each context type
    enum {
      ENCRYPT_WORK=0,
      DECRYPT_WORK,
      READ_LINK_UDP,
      READ_STREAM_UDP,
      READ_TUN,
      READ_BIO_MEMQ_DGRAM,
      READ_BIO_MEMQ_STREAM,
      N_ALIGN_CONTEXTS
    };

    OPENVPN_SIMPLE_EXCEPTION(frame_context_index);

    // We manage an array of Context objects, one for each
    // Frame context above.
    class Context
    {
    public:
      Context()
      {
	headroom_ = 0;
	payload_ = 0;
	tailroom_ = 0;
	buffer_flags_ = 0;
	align_adjust_ = 0;

	adj_headroom_ = 0;
	adj_capacity_ = 0;
      }

      Context(const size_t headroom,
	      const size_t payload,
	      const size_t tailroom,
	      const unsigned int align_adjust, // length of leading prefix data before the data that needs to be aligned on a size_t boundary
	      const unsigned int buffer_flags) // flags passed to BufferAllocated constructor
      {
	headroom_ = headroom;
	payload_ = payload;
	tailroom_ = tailroom;
	buffer_flags_ = buffer_flags;
	align_adjust_ = align_adjust;
	recalc_derived();
      }

      size_t headroom() const { return adj_headroom_; }
      size_t payload() const { return payload_; }
      size_t tailroom() const { return tailroom_; }
      size_t capacity() const { return adj_capacity_; }
      size_t buffer_flags() const { return buffer_flags_; }

      // Calculate a starting offset into a buffer object, dealing with
      // headroom and alignment issues.
      void prepare(BufferAllocated& buf) const
      {
	buf.reset (headroom(), capacity(), buffer_flags());
      }

      // Return a new BufferAllocated object initialized with the given data
      BufferPtr alloc_with_data(const unsigned char *data, const size_t size) const
      {
	const size_t cap = size + headroom() + tailroom();
	BufferPtr b = new BufferAllocated(cap, buffer_flags());
	b->init_headroom(headroom());
	b->write(data, size);
	return b;
      }

      // How much payload space left in buffer
      size_t remaining_payload(const Buffer& buf) const
      {
	if (payload() > buf.size())
	  return payload() - buf.size();
	else
	  return 0;
      }

      std::string info() const
      {
	std::ostringstream info;
	info << "head=" << headroom_ << "[" << adj_headroom_ << "] "
	     << "pay=" << payload_ << " "
	     << "tail=" << tailroom_ << " "
	     << "cap=" << adj_capacity_ << " "
	     << "bf=" << buffer_flags_ << " "
	     << "align=" << align_adjust_;
	return info.str();
      }

    private:
      // recalculate derived values when object parameters are modified
      void recalc_derived()
      {
	// calculate adjusted headroom due to alignment
	adj_headroom_ = adjusted_headroom();

	// calculate capacity
	adj_capacity_ = adj_headroom_ + payload_ + tailroom_;
      }

      // add a small delta to headroom so that the point after the first align_adjust
      // bytes of the buffer will be aligned on a size_t boundary
      size_t adjusted_headroom() const
      {
	const size_t PAYLOAD_ALIGN = sizeof(size_t);
	const size_t delta = ((PAYLOAD_ALIGN << 24) - (headroom_ + align_adjust_)) & (PAYLOAD_ALIGN - 1);
	return headroom_ + delta;
      }

      // parameters
      size_t headroom_;
      size_t payload_;
      size_t tailroom_;
      unsigned int buffer_flags_;
      unsigned int align_adjust_;

      // derived
      size_t adj_headroom_;
      size_t adj_capacity_;
    };

    Frame() {}

    explicit Frame(const Context& c) { set_default_context(c); }

    // set the default context
    void set_default_context(const Context& c)
    {
      for (int i = 0; i < N_ALIGN_CONTEXTS; ++i)
	contexts[i] = c;
    }

    // Calculate a starting offset into a buffer object, dealing with
    // headroom and alignment issues.  context should be one of
    // the context types above.
    void prepare(const unsigned int context, BufferAllocated& buf) const
    {
      (*this)[context].prepare(buf);
    }

    size_t n_contexts() const { return N_ALIGN_CONTEXTS; }

    Context& operator[](const size_t i)
    {
      if (i >= N_ALIGN_CONTEXTS)
	throw frame_context_index();
      return contexts[i];
    }

    const Context& operator[](const size_t i) const
    {
      if (i >= N_ALIGN_CONTEXTS)
	throw frame_context_index();
      return contexts[i];
    }

  private:
    Context contexts[N_ALIGN_CONTEXTS];
  };

  typedef boost::intrusive_ptr<Frame> FramePtr;

} // namespace openvpn

#endif // OPENVPN_FRAME_FRAME
