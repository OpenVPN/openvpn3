//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// These templates define the fundamental data buffer classes used by the
// OpenVPN core.  Normally OpenVPN uses buffers of unsigned chars, but the
// templatization of the classes would allow buffers of other types to
// be defined.
//
// Fundamentally a buffer is an object with 4 fields:
//
// 1. a pointer to underlying data array
// 2. the capacity of the underlying data array
// 3. an offset into the data array
// 4. the size of the referenced data within the array
//
// The BufferType template is the lowest-level buffer class template.  It refers
// to a buffer but without any notion of ownership of the underlying data.
//
// The BufferAllocatedType template is a higher-level template that inherits
// from BufferType but which asserts ownership over the resources of the buffer --
// for example, it will free the underlying buffer in its destructor.
//
// Since most of the time, we want our buffers to be made out of unsigned chars,
// some typedefs at the end of the file define common instantations for the
// BufferType and BufferAllocatedType templates.
//
// Buffer            : a simple buffer of unsigned char without ownership semantics
// ConstBuffer       : like buffer but where the data pointed to by the buffer is const
// BufferAllocated   : an allocated Buffer with ownership semantics
// BufferPtr         : a smart, reference-counted pointer to a BufferAllocated

#ifndef OPENVPN_BUFFER_BUFFER_H
#define OPENVPN_BUFFER_BUFFER_H

#include <string>
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
#define OPENVPN_BUFFER_THROW(exc) { throw BufferException(BufferException::exc); }
#endif

namespace openvpn {

  // special-purpose exception class for Buffer classes
  class BufferException : public std::exception
  {
  public:
    enum Status {
      buffer_full,
      buffer_headroom,
      buffer_underflow,
      buffer_overflow,
      buffer_index,
      buffer_const_index,
      buffer_push_front_headroom,
      buffer_no_reset_impl,
      buffer_pop_back,
      buffer_set_size,
    };

    BufferException(Status status)
      : status_(status) {}

    Status status() const { return status_; }

    const char *status_string() const
    {
      switch (status_)
	{
	case buffer_full:
	  return "buffer_full";
	case buffer_headroom:
	  return "buffer_headroom";
	case buffer_underflow:
	  return "buffer_underflow";
	case buffer_overflow:
	  return "buffer_overflow";
	case buffer_index:
	  return "buffer_index";
	case buffer_const_index:
	  return "buffer_const_index";
	case buffer_push_front_headroom:
	  return "buffer_push_front_headroom";
	case buffer_no_reset_impl:
	  return "buffer_no_reset_impl";
	case buffer_pop_back:
	  return "buffer_pop_back";
	case buffer_set_size:
	  return "buffer_set_size";
	default:
	  return "buffer_???";
	}
    }

    virtual const char* what() const throw() {
      return status_string();
    }
    virtual ~BufferException() throw() {}

  private:
    Status status_;
  };

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

    void reset_content()
    {
      offset_ = size_ = 0;
    }

    // return a const pointer to start of array
    const T* c_data() const { return data_ + offset_; }

    // return a mutable pointer to start of array
    T* data() { return data_ + offset_; }

    // return a const pointer to end of array
    const T* c_data_end() const { return data_ + offset_ + size_; }

    // return a mutable pointer to end of array
    T* data_end() { return data_ + offset_ + size_; }

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

    // return true if data memory is defined
    bool allocated() const { return data_ != NULL; }

    // return true if array is empty
    bool empty() const { return !size_; }

    // return contents of buffer as a std::string
    std::string to_string() const
    {
      return std::string((const char *)c_data(), size());
    }

    // return the number of additional T objects that can be added before capacity is reached (without considering resize)
    size_t remaining(const size_t tailroom = 0) const {
      const size_t r = capacity_ - (offset_ + size_ + tailroom);
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
      if (size > max_size())
	OPENVPN_BUFFER_THROW(buffer_set_size);
      size_ = size;
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

    T pop_back()
    {
      if (!size_)
	OPENVPN_BUFFER_THROW(buffer_pop_back);
      return *(data()+(--size_));
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

    bool contains_null() const
    {
      const T* end = c_data_end();
      for (const T* p = c_data(); p < end; ++p)
	{
	  if (!*p)
	    return true;
	}
      return false;
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

    bool operator==(const BufferType& other) const
    {
      if (size_ != other.size_)
	return false;
      return std::memcmp(c_data(), other.c_data(), size_) == 0;
    }

    bool operator!=(const BufferType& other) const
    {
      return !(*this == other);
    }

    // return a boost::asio::mutable_buffers_1 object used by
    // asio read methods.
    boost::asio::mutable_buffers_1 mutable_buffers_1(const size_t tailroom = 0)
    {
      return boost::asio::mutable_buffers_1(data(), remaining(tailroom));
    }

    // return a boost::asio::const_buffers_1 object used by
    // asio write methods.
    boost::asio::const_buffers_1 const_buffers_1() const
    {
      return boost::asio::const_buffers_1(c_data(), size());
    }

    void realign(size_t headroom)
    {
      if (headroom + size_ > capacity_)
	OPENVPN_BUFFER_THROW(buffer_headroom);
      std::memmove(data_ + headroom, data_ + offset_, size_);
      offset_ = headroom;
    }

    void write(const T* data, const size_t size)
    {
      std::memcpy(write_alloc(size), data, size * sizeof(T));
    }

    void prepend(const T* data, const size_t size)
    {
      std::memcpy(prepend_alloc(size), data, size * sizeof(T));
    }

    void read(T* data, const size_t size)
    {
      std::memcpy(data, read_alloc(size), size * sizeof(T));
    }

    T* write_alloc(const size_t size)
    {
      if (size > remaining())
	resize(offset_ + size_ + size);
      T* ret = data() + size_;
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
	{
	  OPENVPN_BUFFER_THROW(buffer_full);
	}
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
	    std::memset(data_, 0, capacity * sizeof(T));
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
	  std::memcpy(data_, data, size * sizeof(T));
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
            std::memcpy(data_ + offset_, other.data_ + offset_, size_ * sizeof(T));
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
	    std::memcpy(data_ + offset_, other.c_data(), size_ * sizeof(T));
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
	    std::memcpy(data_ + offset_, other.data_ + offset_, size_ * sizeof(T));
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
	    {
	      data_ = new T[capacity];
	    }
	  capacity_ = capacity;
	}
      if ((flags & CONSTRUCT_ZERO) && capacity)
	std::memset(data_, 0, capacity * sizeof(T));
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
      std::memcpy(data_, data, size * sizeof(T));
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
		std::memcpy(data + offset_, data_ + offset_, size_ * sizeof(T));
	      delete_(data_, capacity_, flags_);
	      data_ = data;
	      //std::cout << "*** RESIZE " << capacity_ << " -> " << newcap << std::endl; // fixme
	      capacity_ = newcap;
	    }
	  else
	    {
	      OPENVPN_BUFFER_THROW(buffer_full);
	    }
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
	std::memset(data, 0, size * sizeof(T));
      delete [] data;
    }

    unsigned int flags_;
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
