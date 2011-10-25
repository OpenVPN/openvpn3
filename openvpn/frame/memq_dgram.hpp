#ifndef OPENVPN_FRAME_MEMQ_DGRAM
#define OPENVPN_FRAME_MEMQ_DGRAM

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/buffer/memq.hpp>
#include <openvpn/frame/frame.hpp>

namespace openvpn {

  class MemQDgram : public MemQBase {
  public:
    OPENVPN_SIMPLE_EXCEPTION(frame_uninitialized);

    MemQDgram() {}
    explicit MemQDgram(FramePtr& frame) : frame_(frame) {}
    void set_frame(FramePtr& frame) { frame_ = frame; }

    size_t pending() const
    {
      return empty() ? 0 : q.front()->size();
    }

    void write(const unsigned char *data, size_t size)
    {
      if (frame_)
	{
	  const Frame::Context& fc = (*frame_)[Frame::READ_BIO_MEMQ_STREAM];
	  q.push_back(fc.alloc_with_data(data, size));
	  length += size;
	}
      else
	throw frame_uninitialized();
    }

    size_t read(unsigned char *data, size_t len)
    {
      BufferPtr& b = q.front();
      if (len > b->size())
	len = b->size();
      b->read(data, len);
      if (b->empty())
	q.pop_front();
      length -= len;
      return len;
    }

  private:
    FramePtr frame_;
  };

} // namespace openvpn

#endif // OPENVPN_FRAME_MEMQ_DGRAM
