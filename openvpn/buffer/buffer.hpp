#ifndef OPENVPN_BUFFER_BUFFER_H
#define OPENVPN_BUFFER_BUFFER_H

#include <boost/noncopyable.hpp>
#include <boost/intrusive_ptr.hpp>
#include <boost/asio.hpp>

#include <openvpn/common/rc.hpp>

namespace openvpn {

  class Buffer {
  public:
    Buffer()
    {
      size_ = offset_ = 0;
      data_ = NULL;
    }

    Buffer(void *data, size_t size)
    {
      data_ = (unsigned char *)data;
      size_ = capacity_ = size;
      offset_ = 0;
    }

    unsigned const char *c_data() const { return data_ + offset_; }
    unsigned char *data() { return data_ + offset_; }
    size_t size() const { return size_; }
    bool empty() const { return !size_; }

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

    size_t read(void *out, size_t len)
    {
      if (len > size_)
	len = size_;
      std::memcpy(out, data(), len);
      size_ -= len;
      offset_ += len;
      return len;
    }

    boost::asio::mutable_buffers_1 mutable_buffers_1()
    {
      return boost::asio::mutable_buffers_1(data(), remaining());
    }

    boost::asio::const_buffers_1 const_buffers_1()
    {
      return boost::asio::const_buffers_1(c_data(), size());
    }

  protected:
    unsigned char *data_;
    size_t offset_;
    size_t size_;
    size_t capacity_;
  };

  class BufferAllocated : public Buffer, boost::noncopyable {
  public:
    BufferAllocated(size_t capacity)
    {
      data_ = new unsigned char[capacity_ = capacity];
    }

    BufferAllocated(const void *data, size_t size)
    {
      data_ = new unsigned char[size_ = capacity_ = size];
      memcpy(data_, data, size);
      offset_ = 0;
    }

    ~BufferAllocated()
    {
      delete data_;
    }
  };

  class BufferRC : public BufferAllocated, public RC {
  public:

    BufferRC(size_t capacity)
      : BufferAllocated(capacity) {}

    BufferRC(const void *data, size_t size)
      : BufferAllocated(data, size) {}

    ~BufferRC() {}
  };

  typedef boost::intrusive_ptr<BufferRC> BufferPtr;

} // namespace openvpn

#endif // OPENVPN_BUFFER_BUFFER_H
