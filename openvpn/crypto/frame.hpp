#ifndef OPENVPN_CRYPTO_FRAME
#define OPENVPN_CRYPTO_FRAME

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

  class Frame
  {
  public:
    // alignment types
    enum {
      ENCRYPT_WORK=0,
      DECRYPT_WORK=1,
      READ_LINK_UDP=2,
      READ_STREAM_UDP=3,
      READ_TUN=4,
      N_ALIGN_TYPES=5
    };

    OPENVPN_SIMPLE_EXCEPTION(frame_size);
    OPENVPN_SIMPLE_EXCEPTION(frame_context);

    Frame()
    {
      init(0, 0);
    }

    Frame(const size_t offset,
	  const size_t size,
	  const unsigned int buffer_flags = 0)
    {
      init(offset, size, buffer_flags);
    }

    void init(const size_t offset,
	      const size_t size,
	      const unsigned int buffer_flags = 0)
    {
      if (!(offset <= size))
	throw frame_size();
      size_ = size;
      offset_ = offset;
      buffer_flags_ = buffer_flags;
      std::memset(align_adjust_, 0, sizeof(align_adjust_));
    }

    // Calculate a starting offset into a buffer object, dealing with
    // headroom and alignment issues.  context should be one of
    // the alignment types above.
    void prepare(BufferAllocated& buf, const unsigned int context) const
    {
      buf.reset (adjusted_headroom(context), size_, buffer_flags_);
    }

    // set alignment adjustment for one of the alignment types
    void set_adjust(const unsigned int context, const size_t adjust)
    {
      if (context >= N_ALIGN_TYPES)
	throw frame_context();
      align_adjust_[context] = adjust;
    }

    size_t adjusted_headroom (const unsigned int context) const
    {
      if (context >= N_ALIGN_TYPES)
	throw frame_context();
      const size_t PAYLOAD_ALIGN = sizeof(size_t);
      const size_t adjust = align_adjust_[context];
      const size_t delta = ((PAYLOAD_ALIGN << 24) - (offset_ + adjust)) & (PAYLOAD_ALIGN - 1);
      return offset_ + delta;
    }

  private:
    size_t size_;
    size_t offset_;
    unsigned int buffer_flags_;
    unsigned int align_adjust_[N_ALIGN_TYPES];
  };

} // namespace openvpn

#endif // OPENVPN_CRYPTO_FRAME
