#ifndef OPENVPN_COMMON_SIMPLEARRAY_H
#define OPENVPN_COMMON_SIMPLEARRAY_H

#include <cstring>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {

  /*
   * A variable length array for simple types
   * (no complex constructors or destructors).
   */
  template <typename T>
  class SimpleArray
  {
  public:
    OPENVPN_SIMPLE_EXCEPTION(simple_array_index);
    OPENVPN_SIMPLE_EXCEPTION(simple_array_const_index);

    SimpleArray() : data_(NULL), size_(0) {}

    explicit SimpleArray(const size_t size, const bool zero = false)
    {
      size_ = size;
      data_ = NULL;
      if (size_)
	{
	  data_ = new T[size_];
	  if (zero)
	    std::memset(data_, 0, sizeof(T[size_]));
	}
    }

    explicit SimpleArray(const T* src, const size_t size)
    {
      size_ = size;
      if (size_)
	{
	  data_ = new T[size_];
	  std::memcpy(data_, src, sizeof(T[size_]));
	}
    }

    SimpleArray(const SimpleArray& other)
    {
      data_ = NULL;
      size_ = other.size_;
      if (size_)
	{
	  data_ = new T[size_];
	  std::memcpy(data_, other.data_, sizeof(T[size_]));
	}
    }

    void operator=(const SimpleArray& other)
    {
      init(other.data_, other.size_);
    }

    void init(const size_t size, const bool zero = false)
    {
      if (data_)
	{
	  delete [] data_;
	  data_ = NULL;
	}
      size_ = size;
      if (size_)
	{
	  data_ = new T[size_];
	  if (zero)
	    std::memset(data_, 0, sizeof(T[size_]));
	}
    }

    void init(const T* src, const size_t size)
    {
      if (size_ != size)
	{
	  if (data_)
	    {
	      delete [] data_;
	      data_ = NULL;
	    }
	  size_ = size;
	  if (size_)
	    data_ = new T[size_];
	}
      if (size_)
	std::memcpy(data_, src, sizeof(T[size_]));
    }

    ~SimpleArray()
    {
      if (data_)
	delete [] data_;
    }

    size_t size() const { return size_; }
    size_t bytes() const { return sizeof(T[size_]); }

    const T* data() const { return data_; };
    T* data() { return data_; };

    T& operator[](const size_t index)
    {
      if (index >= size_)
	throw simple_array_index();
      return data_[index];
    }

    const T& operator[](const size_t index) const
    {
      if (index >= size_)
	throw simple_array_const_index();
      return data_[index];
    }

  private:
    T *data_;
    size_t size_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_SIMPLEARRAY_H
