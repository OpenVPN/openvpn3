#ifndef OPENVPN_COMMON_SIMPLEARRAY_H
#define OPENVPN_COMMON_SIMPLEARRAY_H

#include <cstring>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {

  /*
   * A variable length array for simple types, i.e.
   * those having trivial constructors/destructors.
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
      data_ = NULL;
      size_ = size;
      if (size)
	{
	  data_ = new T[size];
	  if (zero)
	    std::memset(data_, 0, sizeof(T[size]));
	}
    }

    explicit SimpleArray(const T* src, const size_t size)
    {
      data_ = NULL;
      size_ = size;
      if (size)
	{
	  data_ = new T[size];
	  std::memcpy(data_, src, sizeof(T[size]));
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
      if (this != &other)
	init(other.data_, other.size_);
    }

    void init(const size_t size, const bool zero = false)
    {
      erase();
      if (size)
	{
	  data_ = new T[size];
	  size_ = size;
	  if (zero)
	    std::memset(data_, 0, sizeof(T[size]));
	}
    }

    void init(const T* src, const size_t size)
    {
      if (size_ != size)
	{
	  erase();
	  if (size)
	    {
	      data_ = new T[size];
	      size_ = size;
	    }
	}
      if (size)
	std::memcpy(data_, src, sizeof(T[size]));
    }

    void erase()
    {
      if (data_)
	{
	  delete [] data_;
	  data_ = NULL;
	}
      size_ = 0;
    }

    void move(SimpleArray& other)
    {
      if (data_)
	delete [] data_;
      data_ = other.data_;
      size_ = other.size_;
      other.data_ = NULL;
      other.size_ = 0;
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
