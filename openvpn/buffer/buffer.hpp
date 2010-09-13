#ifndef OPENVPN_BUFFER_BUFFER_H
#define OPENVPN_BUFFER_BUFFER_H

#include <boost/noncopyable.hpp>

namespace openvpn {
namespace buffer {

class Buffer {
public:
  Buffer()
  {
    size_ = offset_ = 0;
    data_ = NULL;
  }

  unsigned const char *c_data(void) const { return data_ + offset_; }
  unsigned char *data(void) { return data_ + offset_; }
  size_t size(void) const { return size_; }

  size_t remaining() const {
    const size_t ret = capacity_ - offset_;
    return ret <= capacity_ ? ret : 0;
  }

  size_t set_size(const size_t size)
  {
    size_t remain = remaining();
    size_ = size;
    if (size_ > remain)
      size_ = remain;
    return size_;
  }

  boost::asio::mutable_buffers_1 mutable_buffers_1(void)
  {
    return boost::asio::mutable_buffers_1(boost::asio::mutable_buffer(data(), capacity_));
  }

protected:
  unsigned char *data_;
  size_t capacity_;
  size_t size_;
  size_t offset_;
};

class BufferOwned : public Buffer, boost::noncopyable {
public:
  BufferOwned(size_t capacity)
  {
    data_ = new unsigned char[capacity_ = capacity];
  }

  ~BufferOwned()
  {
    delete data_;
  }
};

} // namespace buffer
} // namespace openvpn

#endif // OPENVPN_BUFFER_BUFFER_H
