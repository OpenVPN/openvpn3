#ifndef OPENVPN_BUFFER_BUFFER_H
#define OPENVPN_BUFFER_BUFFER_H

#include <cstring>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/static_assert.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/abort.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>

#ifdef OPENVPN_BUFFER_ABORT
#define OPENVPN_BUFFER_THROW(exc) { abort(); }
#else
#define OPENVPN_BUFFER_THROW(exc) { throw exc(); }
#endif

namespace openvpn {

  OPENVPN_SIMPLE_EXCEPTION(buffer_exception);
  OPENVPN_SIMPLE_EXCEPTION_INHERIT(buffer_exception, buffer_full);
  OPENVPN_SIMPLE_EXCEPTION_INHERIT(buffer_exception, buffer_headroom);
  OPENVPN_SIMPLE_EXCEPTION_INHERIT(buffer_exception, buffer_underflow);
  OPENVPN_SIMPLE_EXCEPTION_INHERIT(buffer_exception, buffer_overflow);
  OPENVPN_SIMPLE_EXCEPTION_INHERIT(buffer_exception, buffer_index);
  OPENVPN_SIMPLE_EXCEPTION_INHERIT(buffer_exception, buffer_const_index);
  OPENVPN_SIMPLE_EXCEPTION_INHERIT(buffer_exception, buffer_push_front_headroom);
  OPENVPN_SIMPLE_EXCEPTION_INHERIT(buffer_exception, buffer_no_reset_impl);

  template <typename T>
  class BufferType {
  public:
    typedef T* type;
    typedef const T* const_type;

    BufferType()
    {
      data_ = NULL;
      offset_ = size_ = capacity_ = 0;
    }

    BufferType(T* data, size_t size, bool filled)
    {
      data_ = data;
      offset_ = 0;
      capacity_ = size;
      size_ = filled ? size : 0;
    }

    void init_headroom(size_t headroom)
    {
      if (headroom > capacity_)
	OPENVPN_BUFFER_THROW(buffer_headroom);
      offset_ = headroom;
      size_ = 0;
    }

    void reset_size()
    {
      size_ = 0;
    }

    // return a const pointer to start of array
    const T* c_data() const { return data_ + offset_; }

    // return a mutable pointer to start of array
    T* data() { return data_ + offset_; }

    // return a const pointer to start of raw data
    const T* c_data_raw() const { return data_; }

    // return a mutable pointer to start of raw data
    T* data_raw() { return data_; }

    // return size of array in T objects
    size_t size() const { return size_; }

    // return raw size of allocated buffer in T objects
    size_t capacity() const { return capacity_; }

    // return current offset (headroom) into buffer
    size_t offset() const { return offset_; }

    // return true if array is not empty
    bool defined() const { return size_ > 0; }

    // return true if array is empty
    bool empty() const { return !size_; }

    // return the number of additional T objects that can be added before capacity is reached (without considering resize)
    size_t remaining() const {
      const size_t r = capacity_ - (offset_ + size_);
      return r <= capacity_ ? r : 0;
    }

    // return the maximum allowable size value in T objects given the current offset (without considering resize)
    size_t max_size() const {
      const size_t r = capacity_ - offset_;
      return r <= capacity_ ? r : 0;
    }

    // After an external method, operating on the array as
    // a mutable unsigned char buffer, has written data to the
    // array, use this method to set the array length in terms
    // of T objects.
    void set_size(const size_t size)
    {
      size_ = std::min(max_size(), size);
    }

    // append a T object to array, with possible resize
    void push_back(const T& value)
    {
      if (!remaining())
	resize(offset_ + size_ + 1);
      *(data()+size_++) = value;
    }

    // append a T object to array, with possible resize
    void push_front(const T& value)
    {
      if (!offset_)
	OPENVPN_BUFFER_THROW(buffer_push_front_headroom);
      --offset_;
      ++size_;
      *data() = value;
    }

    T pop_front()
    {
      T ret = (*this)[0];
      ++offset_;
      --size_;
      return ret;
    }

    void advance(const size_t delta)
    {
      if (delta > size_)
	OPENVPN_BUFFER_THROW(buffer_overflow);
      offset_ += delta;
      size_ -= delta;
    }

    // mutable index into array
    T& operator[](const size_t index)
    {
      if (index >= size_)
	OPENVPN_BUFFER_THROW(buffer_index);
      return data()[index];
    }

    // const index into array
    const T& operator[](const size_t index) const
    {
      if (index >= size_)
	OPENVPN_BUFFER_THROW(buffer_const_index);
      return c_data()[index];
    }

    // return a boost::asio::mutable_buffers_1 object used by
    // asio read methods.
    boost::asio::mutable_buffers_1 mutable_buffers_1()
    {
      return boost::asio::mutable_buffers_1(data(), remaining());
    }

    // return a boost::asio::const_buffers_1 object used by
    // asio write methods.
    boost::asio::const_buffers_1 const_buffers_1() const
    {
      return boost::asio::const_buffers_1(c_data(), size());
    }

    void write(const T* data, const size_t size)
    {
      std::memcpy(write_alloc(size), data, sizeof(T[size]));
    }

    void prepend(const T* data, const size_t size)
    {
      std::memcpy(prepend_alloc(size), data, sizeof(T[size]));
    }

    void read(T* data, const size_t size)
    {
      std::memcpy(data, read_alloc(size), sizeof(T[size]));
    }

    T* write_alloc(const size_t size)
    {
      if (size > remaining())
	resize(offset_ + size_ + size);
      T* ret = data()+size_;
      size_ += size;
      return ret;
    }

    T* prepend_alloc(const size_t size)
    {
      if (size <= offset_)
	{
	  offset_ -= size;
	  size_ += size;
	  return data();
	}
      else
	OPENVPN_BUFFER_THROW(buffer_headroom);
    }

    T* read_alloc(const size_t size)
    {
      if (size <= size_)
	{
	  T* ret = data();
	  offset_ += size;
	  size_ -= size;
	  return ret;
	}
      else
	OPENVPN_BUFFER_THROW(buffer_underflow);
    }

    void reset(const size_t min_capacity, const unsigned int flags)
    {
      if (min_capacity > capacity_)
	reset_impl(min_capacity, flags);
    }

  protected:
    // Called when reset method needs to expand the buffer size
    virtual void reset_impl(const size_t min_capacity, const unsigned int flags)
    {
      OPENVPN_BUFFER_THROW(buffer_no_reset_impl);
    }

    // Derived classes can implement buffer growing semantics
    // by overloading this method.  In the default implementation,
    // buffers are non-growable, so we throw an exception.
    virtual void resize(const size_t new_capacity)
    {
      if (new_capacity > capacity_)
	OPENVPN_BUFFER_THROW(buffer_full);
    }

    T* data_;          // pointer to data
    size_t offset_;    // offset from data_ of beginning of T array (to allow for headroom)
    size_t size_;      // number of T objects in array starting at data_ + offset_
    size_t capacity_;  // maximum number of array objects of type T for which memory is allocated, starting at data_
  };

  template <typename T, typename R = thread_unsafe_refcount>
  class BufferAllocatedType : public BufferType<T>, public RC<R>
  {
    using BufferType<T>::data_;
    using BufferType<T>::offset_;
    using BufferType<T>::size_;
    using BufferType<T>::capacity_;

  public:
    enum {
      CONSTRUCT_ZERO = (1<<0),  // if enabled, constructors/init will zero allocated space
      DESTRUCT_ZERO  = (1<<1),  // if enabled, destructor will zero data before deletion
      GROW  = (1<<2),           // if enabled, buffer will grow (otherwise buffer_full exception will be thrown)
      ARRAY = (1<<3),           // if enabled, use as array
    };

    BufferAllocatedType() { flags_ = 0; }

    BufferAllocatedType(const size_t capacity, const unsigned int flags)
    {
      flags_ = flags;
      capacity_ = capacity;
      if (capacity)
	{
	  data_ = new T[capacity];
	  if (flags & CONSTRUCT_ZERO)
	    std::memset(data_, 0, sizeof(T[capacity]));
	  if (flags & ARRAY)
	    size_ = capacity;
	}
    }

    BufferAllocatedType(const T* data, const size_t size, const unsigned int flags)
    {
      flags_ = flags;
      size_ = capacity_ = size;
      if (size)
	{
	  data_ = new T[size];
	  std::memcpy(data_, data, sizeof(T[size]));
	}
    }

    BufferAllocatedType(const BufferAllocatedType& other)
    {
      offset_ = other.offset_;
      size_ = other.size_;
      capacity_ = other.capacity_;
      flags_ = other.flags_;
      if (capacity_)
        {
          data_ = new T[capacity_];
          if (size_)
            std::memcpy(data_ + offset_, other.data_ + offset_, sizeof(T[size_]));
        }
    }

    template <typename OT>
    BufferAllocatedType(const BufferType<OT>& other, const unsigned int flags)
    {
      BOOST_STATIC_ASSERT(sizeof(T) == sizeof(OT));
      offset_ = other.offset();
      size_ = other.size();
      capacity_ = other.capacity();
      flags_ = flags;
      if (capacity_)
	{
	  data_ = new T[capacity_];
	  if (size_)
	    std::memcpy(data_ + offset_, other.c_data(), sizeof(T[size_]));
	}
    }

    void operator=(const BufferAllocatedType& other)
    {
      if (this != &other)
	{
	  offset_ = size_ = 0;
	  if (capacity_ != other.capacity_)
	    {
	      erase_();
	      if (other.capacity_)
		data_ = new T[other.capacity_];
	      capacity_ = other.capacity_;
	    }
	  offset_ = other.offset_;
	  size_ = other.size_;
	  flags_ = other.flags_;
	  if (size_)
	    std::memcpy(data_ + offset_, other.data_ + offset_, sizeof(T[size_]));
	}
    }

    void init(const size_t capacity, const unsigned int flags)
    {
      offset_ = size_ = 0;
      flags_ = flags;
      if (capacity_ != capacity)
	{
	  erase_();
	  if (capacity)
	      data_ = new T[capacity];
	  capacity_ = capacity;
	}
      if ((flags & CONSTRUCT_ZERO) && capacity)
	std::memset(data_, 0, sizeof(T[capacity]));
      if (flags & ARRAY)
	size_ = capacity;
    }

    void init(const T* data, const size_t size, const unsigned int flags)
    {
      offset_ = size_ = 0;
      flags_ = flags;
      if (size != capacity_)
	{
	  erase_();
	  if (size)
	    data_ = new T[size];
	  capacity_ = size;
	}
      size_ = size;
      std::memcpy(data_, data, sizeof(T[size]));
    }

    void reset(const size_t min_capacity, const unsigned int flags)
    {
      if (min_capacity > capacity_)
	init (min_capacity, flags);
    }

    void move(BufferAllocatedType& other)
    {
      if (data_)
	delete_(data_, capacity_, flags_);

      data_ = other.data_;
      offset_ = other.offset_;
      size_ = other.size_;
      capacity_ = other.capacity_;
      flags_ = other.flags_;

      other.data_ = NULL;
      other.offset_ = other.size_ = other.capacity_ = 0;
    }

    void swap(BufferAllocatedType& other)
    {
      std::swap(data_, other.data_);
      std::swap(offset_, other.offset_);
      std::swap(size_, other.size_);
      std::swap(capacity_, other.capacity_);
      std::swap(flags_, other.flags_);
    }

    void clear()
    {
      erase_();
      flags_ = 0;
      size_ = offset_ = 0;
    }

    void or_flags(const unsigned int flags)
    {
      flags_ |= flags;
    }

    void and_flags(const unsigned int flags)
    {
      flags_ &= flags;
    }

    ~BufferAllocatedType()
    {
      if (data_)
	delete_(data_, capacity_, flags_);
    }

  protected:
    // Called when reset method needs to expand the buffer size
    virtual void reset_impl(const size_t min_capacity, const unsigned int flags)
    {
      init(min_capacity, flags);
    }

    // Set current capacity to at least new_capacity.
    virtual void resize(const size_t new_capacity)
    {
      const size_t newcap = std::max(new_capacity, capacity_ * 2);
      if (newcap > capacity_)
	{
	  if (flags_ & GROW)
	    {
	      T* data = new T[newcap];
	      if (size_)
		std::memcpy(data + offset_, data_ + offset_, sizeof(T[size_]));
	      delete_(data_, capacity_, flags_);
	      data_ = data;
	      //std::cout << "*** RESIZE " << capacity_ << " -> " << newcap << std::endl; // fixme
	      capacity_ = newcap;
	    }
	  else
	    OPENVPN_BUFFER_THROW(buffer_full);
	}
    }

    void erase_()
    {
      if (data_)
	{
	  delete_(data_, capacity_, flags_);
	  data_ = NULL;
	}
      capacity_ = 0;
    }

    static void delete_(T* data, const size_t size, const unsigned int flags)
    {
      if (size && (flags & DESTRUCT_ZERO))
	std::memset(data, 0, sizeof(T[size]));
      delete [] data;
    }

    unsigned long flags_;
  };

  typedef BufferType<unsigned char> Buffer;
  typedef BufferType<const unsigned char> ConstBuffer;
  typedef BufferAllocatedType<unsigned char> BufferAllocated;
  typedef boost::intrusive_ptr<BufferAllocated> BufferPtr;

  template <typename T>
  inline BufferType<const T>& const_buffer_ref(BufferType<T>& src)
  {
    return (BufferType<const T>&)src;
  }

} // namespace openvpn

#endif // OPENVPN_BUFFER_BUFFER_H
