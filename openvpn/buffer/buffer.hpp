//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2022 OpenVPN Inc.
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
// ConstBuffer       : like buffer but where the data pointed to by the buffer is read-only
// BufferAllocated   : an allocated Buffer with ownership semantics
// BufferPtr         : a smart, reference-counted pointer to a BufferAllocated

#pragma once

#include <string>
#include <cstring>
#include <algorithm>
#include <type_traits> // for std::is_nothrow_move_constructible, std::remove_const, std::enable_if, and std::is_const

#ifndef OPENVPN_NO_IO
#include <openvpn/io/io.hpp>
#endif

#include <openvpn/common/size.hpp>
#include <openvpn/common/abort.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/buffer/bufclamp.hpp>

#ifdef OPENVPN_BUFFER_ABORT
#define OPENVPN_BUFFER_THROW(exc) \
    {                             \
        std::abort();             \
    }
#else
#define OPENVPN_BUFFER_THROW(exc)                    \
    {                                                \
        throw BufferException(BufferException::exc); \
    }
#endif

namespace openvpn {

// special-purpose exception class for Buffer classes
class BufferException : public std::exception
{
  public:
    enum Status
    {
        buffer_full,
        buffer_headroom,
        buffer_underflow,
        buffer_overflow,
        buffer_offset,
        buffer_index,
        buffer_const_index,
        buffer_push_front_headroom,
        buffer_no_reset_impl,
        buffer_pop_back,
        buffer_set_size,
        buffer_range,
    };

    explicit BufferException(Status status)
        : status_(status)
    {
    }

    BufferException(Status status, const std::string &msg)
        : status_(status),
          msg_(std::string(status_string(status)) + " : " + msg)
    {
    }

    virtual const char *what() const noexcept
    {
        if (!msg_.empty())
            return msg_.c_str();
        else
            return status_string(status_);
    }

    Status status() const
    {
        return status_;
    }
    virtual ~BufferException() noexcept = default;

  private:
    static const char *status_string(const Status status)
    {
        switch (status)
        {
        case buffer_full:
            return "buffer_full";
        case buffer_headroom:
            return "buffer_headroom";
        case buffer_underflow:
            return "buffer_underflow";
        case buffer_overflow:
            return "buffer_overflow";
        case buffer_offset:
            return "buffer_offset";
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
        case buffer_range:
            return "buffer_range";
        default:
            return "buffer_???";
        }
    }

    Status status_;
    std::string msg_;
};

template <typename T, typename R>
class BufferAllocatedType;

template <typename T>
class BufferType;

template <typename T>
class ConstBufferType
{
  private:
    // allow access to other.data_
    template <typename, typename>
    friend class BufferAllocatedType;

    template <typename>
    friend class BufferType;

  public:
    typedef T value_type;
    typedef T *type;
    typedef const T *const_type;
    typedef typename std::remove_const<T>::type NCT; // non-const type

    ConstBufferType();

    ConstBufferType(void *data, const size_t size, const bool filled);

    // When T is already const, this constructor becomes redundant, so disable it.
    template <typename U = T,
              typename std::enable_if<!std::is_const<U>::value, int>::type = 0>
    ConstBufferType(const void *data, const size_t size, const bool filled);

    ConstBufferType(T *data, const size_t size, const bool filled);

    // When T is already const, this constructor becomes redundant, so disable it.
    template <typename U = T,
              typename std::enable_if<!std::is_const<U>::value, int>::type = 0>
    ConstBufferType(const U *data, const size_t size, const bool filled);

    // const index into array
    auto &operator[](const size_t index) const;
    auto &operator[](const size_t index);

    void init_headroom(const size_t headroom);
    void reset_offset(const size_t offset);
    void reset_size();
    void reset_content();

    // std::string compatible methods
    const T *c_str() const;
    size_t length() const;

    // return a const pointer to start of array
    const T *c_data() const;

    // return a const pointer to end of array
    const T *c_data_end() const;

    // return a const pointer to start of raw data
    const T *c_data_raw() const;

    // return raw size of allocated buffer in T objects
    size_t capacity() const;

    // return current offset (headroom) into buffer
    size_t offset() const;

    // return true if array is not empty
    bool defined() const;

    // return true if data memory is defined
    bool allocated() const;

    // return true if array is empty
    bool empty() const;

    // return size of array in T objects
    size_t size() const;

    T pop_back();
    T pop_front();
    T front() const;
    T back() const;
    void advance(const size_t delta);
    bool contains_null() const;
    bool is_zeroed() const;

#ifndef OPENVPN_NO_IO
    // return a openvpn_io::const_buffer object used by
    // asio write methods.
    openvpn_io::const_buffer const_buffer() const;

    // clamped version of const_buffer()
    openvpn_io::const_buffer const_buffer_clamp() const;

    openvpn_io::const_buffer const_buffer_limit(const size_t limit) const;
#endif

    void read(NCT *data, const size_t size);
    void read(void *data, const size_t size);
    auto *read_alloc(const size_t size);
    auto read_alloc_buf(const size_t size);

    // return the maximum allowable size value in T objects given the current offset (without considering resize)
    size_t max_size() const;

    // After an external method, operating on the array as
    // a mutable unsigned char buffer, has written data to the
    // array, use this method to set the array length in terms
    // of T objects.
    void set_size(const size_t size);

    // Increment size (usually used in a similar context
    // to set_size such as after mutable_buffer_append).
    void inc_size(const size_t delta);

    ConstBufferType range(size_t offset, size_t len) const;

    // const index into array
    const T *c_index(const size_t index) const;

    bool operator==(const ConstBufferType &other) const;
    bool operator!=(const ConstBufferType &other) const;

  protected:
    void reserve(const size_t n);
    T *data();
    T *data_end();
    T *data_raw();
    size_t remaining(const size_t tailroom = 0) const;
    size_t max_size_tailroom(const size_t tailroom) const;
    void push_back(const T &value);
    void push_front(const T &value);
    void set_trailer(const T &value);
    void null_terminate();
    T *index(const size_t index);

#ifndef OPENVPN_NO_IO
    openvpn_io::mutable_buffer mutable_buffer(const size_t tailroom = 0);
    openvpn_io::mutable_buffer mutable_buffer_append(const size_t tailroom = 0);
    openvpn_io::mutable_buffer mutable_buffer_clamp(const size_t tailroom = 0);
    openvpn_io::mutable_buffer mutable_buffer_append_clamp(const size_t tailroom = 0);
#endif

    void realign(size_t headroom);
    void write(const T *data, const size_t size);
    void write(const void *data, const size_t size);
    void prepend(const T *data, const size_t size);
    void prepend(const void *data, const size_t size);
    T *write_alloc(const size_t size);
    T *prepend_alloc(const size_t size);
    void reset(const size_t min_capacity, const unsigned int flags);
    void reset(const size_t headroom, const size_t min_capacity, const unsigned int flags);
    template <typename B>
    void append(const B &other);

    virtual void reset_impl(const size_t min_capacity, const unsigned int flags);
    virtual void resize(const size_t new_capacity);
    void buffer_full_error(const size_t newcap, const bool allocated) const;


  protected:
    ConstBufferType(T *data, const size_t offset, const size_t size, const size_t capacity);

    // When T is already const, this constructor becomes redundant, so disable it.
    template <typename U = T,
              typename std::enable_if<!std::is_const<U>::value, int>::type = 0>
    ConstBufferType(const U *data, const size_t offset, const size_t size, const size_t capacity);

    // Even though *data_ is declared as non-const, within ConstBufferType
    // we MUST always treat it as const.  But derived classes may treat it
    // as non-const as long as they passed in non-const data to begin with.
    T *data_;         // pointer to data
    size_t offset_;   // offset from data_ of beginning of T array (to allow for headroom)
    size_t size_;     // number of T objects in array starting at data_ + offset_
    size_t capacity_; // maximum number of array objects of type T for which memory is allocated, starting at data_
};

// Member function definitions

template <typename T>
ConstBufferType<T>::ConstBufferType()
{
    static_assert(std::is_nothrow_move_constructible<ConstBufferType>::value, "class ConstBufferType not noexcept move constructable");
    data_ = nullptr;
    offset_ = size_ = capacity_ = 0;
}

template <typename T>
ConstBufferType<T>::ConstBufferType(void *data, const size_t size, const bool filled)
    : ConstBufferType((T *)data, size, filled)
{
}

template <typename T>
template <typename U, typename std::enable_if<!std::is_const<U>::value, int>::type>
ConstBufferType<T>::ConstBufferType(const void *data, const size_t size, const bool filled)
    : ConstBufferType(const_cast<void *>(data), size, filled)
{
}

template <typename T>
ConstBufferType<T>::ConstBufferType(T *data, const size_t size, const bool filled)
{
    data_ = data;
    offset_ = 0;
    capacity_ = size;
    size_ = filled ? size : 0;
}

template <typename T>
template <typename U, typename std::enable_if<!std::is_const<U>::value, int>::type>
ConstBufferType<T>::ConstBufferType(const U *data, const size_t size, const bool filled)
    : ConstBufferType(const_cast<U *>(data), size, filled)
{
}

template <typename T>
auto &ConstBufferType<T>::operator[](const size_t index) const
{
    if (index >= size_)
        OPENVPN_BUFFER_THROW(buffer_const_index);
    return c_data()[index];
}

template <typename T>
auto &ConstBufferType<T>::operator[](const size_t index)
{
    if (index >= size_)
        OPENVPN_BUFFER_THROW(buffer_const_index);
    if constexpr (std::is_same_v<ConstBufferType<T>, decltype(*this)>)
        return c_data()[index];
    else
        return data()[index];
}

template <typename T>
void ConstBufferType<T>::init_headroom(const size_t headroom)
{
    if (headroom > capacity_)
        OPENVPN_BUFFER_THROW(buffer_headroom);
    offset_ = headroom;
    size_ = 0;
}

template <typename T>
void ConstBufferType<T>::reset_offset(const size_t offset)
{
    const size_t size = size_ + offset_ - offset;
    if (offset > capacity_ || size > capacity_ || offset + size > capacity_)
        OPENVPN_BUFFER_THROW(buffer_offset);
    offset_ = offset;
    size_ = size;
}

template <typename T>
void ConstBufferType<T>::reset_size()
{
    size_ = 0;
}

template <typename T>
void ConstBufferType<T>::reset_content()
{
    offset_ = size_ = 0;
}

template <typename T>
const T *ConstBufferType<T>::c_str() const
{
    return c_data();
}

template <typename T>
size_t ConstBufferType<T>::length() const
{
    return size();
}

template <typename T>
const T *ConstBufferType<T>::c_data() const
{
    return data_ + offset_;
}

template <typename T>
const T *ConstBufferType<T>::c_data_end() const
{
    return data_ + offset_ + size_;
}

template <typename T>
const T *ConstBufferType<T>::c_data_raw() const
{
    return data_;
}

template <typename T>
size_t ConstBufferType<T>::capacity() const
{
    return capacity_;
}

template <typename T>
size_t ConstBufferType<T>::offset() const
{
    return offset_;
}

template <typename T>
bool ConstBufferType<T>::defined() const
{
    return size_ > 0;
}

template <typename T>
bool ConstBufferType<T>::allocated() const
{
    return data_ != nullptr;
}

template <typename T>
bool ConstBufferType<T>::empty() const
{
    return !size_;
}

template <typename T>
size_t ConstBufferType<T>::size() const
{
    return size_;
}

template <typename T>
T ConstBufferType<T>::pop_back()
{
    if (!size_)
        OPENVPN_BUFFER_THROW(buffer_pop_back);
    return *(c_data() + (--size_));
}

template <typename T>
T ConstBufferType<T>::pop_front()
{
    T ret = (*this)[0];
    ++offset_;
    --size_;
    return ret;
}

template <typename T>
T ConstBufferType<T>::front() const
{
    return (*this)[0];
}

template <typename T>
T ConstBufferType<T>::back() const
{
    return (*this)[size_ - 1];
}

template <typename T>
void ConstBufferType<T>::advance(const size_t delta)
{
    if (delta > size_)
        OPENVPN_BUFFER_THROW(buffer_overflow);
    offset_ += delta;
    size_ -= delta;
}

template <typename T>
bool ConstBufferType<T>::contains_null() const
{
    const T *end = c_data_end();
    for (const T *p = c_data(); p < end; ++p)
    {
        if (!*p)
            return true;
    }
    return false;
}

template <typename T>
bool ConstBufferType<T>::is_zeroed() const
{
    const T *end = c_data_end();
    for (const T *p = c_data(); p < end; ++p)
    {
        if (*p)
            return false;
    }
    return true;
}

#ifndef OPENVPN_NO_IO
template <typename T>
openvpn_io::const_buffer ConstBufferType<T>::const_buffer() const
{
    return openvpn_io::const_buffer(c_data(), size());
}

template <typename T>
openvpn_io::const_buffer ConstBufferType<T>::const_buffer_clamp() const
{
    return openvpn_io::const_buffer(c_data(), buf_clamp_write(size()));
}

template <typename T>
openvpn_io::const_buffer ConstBufferType<T>::const_buffer_limit(const size_t limit) const
{
    return openvpn_io::const_buffer(c_data(), std::min(buf_clamp_write(size()), limit));
}
#endif

template <typename T>
void ConstBufferType<T>::read(NCT *data, const size_t size)
{
    std::memcpy(data, read_alloc(size), size * sizeof(T));
}

template <typename T>
void ConstBufferType<T>::read(void *data, const size_t size)
{
    read((NCT *)data, size);
}

template <typename T>
auto *ConstBufferType<T>::read_alloc(const size_t size)
{
    if (size <= size_)
    {
        using retT = std::conditional_t<std::is_same_v<decltype(*this), ConstBufferType<T>>, const value_type, value_type>;
        retT *ret;
        if constexpr (std::is_const_v<retT>)
            ret = c_data();
        else
            ret = data();
        offset_ += size;
        size_ -= size;
        return ret;
    }
    else
        OPENVPN_BUFFER_THROW(buffer_underflow);
}

template <typename T>
auto ConstBufferType<T>::read_alloc_buf(const size_t size)
{
    if (size <= size_)
    {
        using retT = std::conditional_t<std::is_same_v<decltype(*this), ConstBufferType<T>>, ConstBufferType<T>, BufferType<T>>;
        retT ret(data_, offset_, size, capacity_);
        offset_ += size;
        size_ -= size;
        return ret;
    }
    else
        OPENVPN_BUFFER_THROW(buffer_underflow);
}

template <typename T>
size_t ConstBufferType<T>::max_size() const
{
    const size_t r = capacity_ - offset_;
    return r <= capacity_ ? r : 0;
}

template <typename T>
void ConstBufferType<T>::set_size(const size_t size)
{
    if (size > max_size())
        OPENVPN_BUFFER_THROW(buffer_set_size);
    size_ = size;
}

template <typename T>
void ConstBufferType<T>::inc_size(const size_t delta)
{
    set_size(size_ + delta);
}

template <typename T>
ConstBufferType<T> ConstBufferType<T>::range(size_t offset, size_t len) const
{
    if (offset + len > size())
    {
        if (offset < size())
            len = size() - offset;
        else
            len = 0;
    }
    return ConstBufferType(c_data(), offset, len, len);
}

template <typename T>
const T *ConstBufferType<T>::c_index(const size_t index) const
{
    if (index >= size_)
        OPENVPN_BUFFER_THROW(buffer_const_index);
    return &c_data()[index];
}

template <typename T>
bool ConstBufferType<T>::operator==(const ConstBufferType &other) const
{
    if (size_ != other.size_)
        return false;
    return std::memcmp(c_data(), other.c_data(), size_) == 0;
}

template <typename T>
bool ConstBufferType<T>::operator!=(const ConstBufferType &other) const
{
    return !(*this == other);
}

template <typename T>
ConstBufferType<T>::ConstBufferType(T *data, const size_t offset, const size_t size, const size_t capacity)
    : data_(data), offset_(offset), size_(size), capacity_(capacity)
{
}

template <typename T>
template <typename U, typename std::enable_if<!std::is_const<U>::value, int>::type>
ConstBufferType<T>::ConstBufferType(const U *data, const size_t offset, const size_t size, const size_t capacity)
    : ConstBufferType(const_cast<U *>(data), offset, size, capacity)
{
}


template <typename T>
void ConstBufferType<T>::reserve(const size_t n)
{
    if (n > capacity_)
        resize(n);
}

template <typename T>
T *ConstBufferType<T>::data()
{
    return data_ + offset_;
}

template <typename T>
T *ConstBufferType<T>::data_end()
{
    return data_ + offset_ + size_;
}

template <typename T>
T *ConstBufferType<T>::data_raw()
{
    return data_;
}

template <typename T>
size_t ConstBufferType<T>::remaining(const size_t tailroom) const
{
    const size_t r = capacity_ - (offset_ + size_ + tailroom);
    return r <= capacity_ ? r : 0;
}

template <typename T>
size_t ConstBufferType<T>::max_size_tailroom(const size_t tailroom) const
{
    const size_t r = capacity_ - (offset_ + tailroom);
    return r <= capacity_ ? r : 0;
}

template <typename T>
void ConstBufferType<T>::push_back(const T &value)
{
    if (!remaining())
        resize(offset_ + size_ + 1);
    *(data() + size_++) = value;
}

template <typename T>
void ConstBufferType<T>::push_front(const T &value)
{
    if (!offset_)
        OPENVPN_BUFFER_THROW(buffer_push_front_headroom);
    --offset_;
    ++size_;
    *data() = value;
}

template <typename T>
void ConstBufferType<T>::set_trailer(const T &value)
{
    if (!remaining())
        resize(offset_ + size_ + 1);
    *(data() + size_) = value;
}

template <typename T>
void ConstBufferType<T>::null_terminate()
{
    if (empty() || back())
        push_back(0);
}

template <typename T>
T *ConstBufferType<T>::index(const size_t index)
{
    if (index >= size_)
        OPENVPN_BUFFER_THROW(buffer_index);
    return &data()[index];
}

#ifndef OPENVPN_NO_IO
template <typename T>
openvpn_io::mutable_buffer ConstBufferType<T>::mutable_buffer(const size_t tailroom)
{
    return openvpn_io::mutable_buffer(data(), max_size_tailroom(tailroom));
}

template <typename T>
openvpn_io::mutable_buffer ConstBufferType<T>::mutable_buffer_append(const size_t tailroom)
{
    return openvpn_io::mutable_buffer(data_end(), remaining(tailroom));
}

template <typename T>
openvpn_io::mutable_buffer ConstBufferType<T>::mutable_buffer_clamp(const size_t tailroom)
{
    return openvpn_io::mutable_buffer(data(), buf_clamp_read(max_size_tailroom(tailroom)));
}

template <typename T>
openvpn_io::mutable_buffer ConstBufferType<T>::mutable_buffer_append_clamp(const size_t tailroom)
{
    return openvpn_io::mutable_buffer(data_end(), buf_clamp_read(remaining(tailroom)));
}
#endif

template <typename T>
void ConstBufferType<T>::realign(size_t headroom)
{
    if (headroom != offset_)
    {
        if (headroom + size_ > capacity_)
            OPENVPN_BUFFER_THROW(buffer_headroom);
        std::memmove(data_ + headroom, data_ + offset_, size_);
        offset_ = headroom;
    }
}

template <typename T>
void ConstBufferType<T>::write(const T *data, const size_t size)
{
    std::memcpy(write_alloc(size), data, size * sizeof(T));
}

template <typename T>
void ConstBufferType<T>::write(const void *data, const size_t size)
{
    write((const T *)data, size);
}

template <typename T>
void ConstBufferType<T>::prepend(const T *data, const size_t size)
{
    std::memcpy(prepend_alloc(size), data, size * sizeof(T));
}

template <typename T>
void ConstBufferType<T>::prepend(const void *data, const size_t size)
{
    prepend((const T *)data, size);
}

template <typename T>
T *ConstBufferType<T>::write_alloc(const size_t size)
{
    if (size > remaining())
        resize(offset_ + size_ + size);
    T *ret = data() + size_;
    size_ += size;
    return ret;
}

template <typename T>
T *ConstBufferType<T>::prepend_alloc(const size_t size)
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

template <typename T>
void ConstBufferType<T>::reset(const size_t min_capacity, const unsigned int flags)
{
    if (min_capacity > capacity_)
        reset_impl(min_capacity, flags);
}

template <typename T>
void ConstBufferType<T>::reset(const size_t headroom, const size_t min_capacity, const unsigned int flags)
{
    reset(min_capacity, flags);
    init_headroom(headroom);
}

template <typename T>
template <typename B>
void ConstBufferType<T>::append(const B &other)
{
    write(other.c_data(), other.size());
}

template <typename T>
void ConstBufferType<T>::reset_impl(const size_t min_capacity, const unsigned int flags)
{
    OPENVPN_BUFFER_THROW(buffer_no_reset_impl);
}

template <typename T>
void ConstBufferType<T>::resize(const size_t new_capacity)
{
    if (new_capacity > capacity_)
        buffer_full_error(new_capacity, false);
}

template <typename T>
void ConstBufferType<T>::buffer_full_error(const size_t newcap, const bool allocated) const
{
#ifdef OPENVPN_BUFFER_ABORT
    std::abort();
#else
    throw BufferException(BufferException::buffer_full, "allocated=" + std::to_string(allocated) + " size=" + std::to_string(size_) + " offset=" + std::to_string(offset_) + " capacity=" + std::to_string(capacity_) + " newcap=" + std::to_string(newcap));
#endif
}

template <typename T>
class BufferType : public ConstBufferType<T>
{
  private:
    // allow access to other.data_
    template <typename, typename>
    friend class BufferAllocatedType;

    template <typename>
    friend class ConstBufferType;

  public:
    using ConstBufferType<T>::empty;
    using ConstBufferType<T>::capacity;
    using ConstBufferType<T>::offset;
    using ConstBufferType<T>::back;
    using ConstBufferType<T>::init_headroom;
    using ConstBufferType<T>::operator[];
    using ConstBufferType<T>::reserve;
    using ConstBufferType<T>::data;
    using ConstBufferType<T>::data_end;
    using ConstBufferType<T>::data_raw;
    using ConstBufferType<T>::remaining;
    using ConstBufferType<T>::max_size_tailroom;
    using ConstBufferType<T>::push_back;
    using ConstBufferType<T>::push_front;
    using ConstBufferType<T>::set_trailer;
    using ConstBufferType<T>::null_terminate;
    using ConstBufferType<T>::index;
#ifndef OPENVPN_NO_IO
    using ConstBufferType<T>::mutable_buffer;
    using ConstBufferType<T>::mutable_buffer_append;
    using ConstBufferType<T>::mutable_buffer_clamp;
    using ConstBufferType<T>::mutable_buffer_append_clamp;
#endif
    using ConstBufferType<T>::realign;
    using ConstBufferType<T>::write;
    using ConstBufferType<T>::prepend;
    using ConstBufferType<T>::write_alloc;
    using ConstBufferType<T>::prepend_alloc;
    using ConstBufferType<T>::reset;
    using ConstBufferType<T>::append;
    using ConstBufferType<T>::reset_impl;
    using ConstBufferType<T>::resize;
    using ConstBufferType<T>::buffer_full_error;


    BufferType();
    BufferType(void *data, const size_t size, const bool filled);
    BufferType(T *data, const size_t size, const bool filled);

  protected:
    BufferType(T *data, const size_t offset, const size_t size, const size_t capacity);
};

// Member function definitions

template <typename T>
BufferType<T>::BufferType()
{
}

template <typename T>
BufferType<T>::BufferType(void *data, const size_t size, const bool filled)
    : ConstBufferType<T>(data, size, filled)
{
}

template <typename T>
BufferType<T>::BufferType(T *data, const size_t size, const bool filled)
    : ConstBufferType<T>(data, size, filled)
{
}

template <typename T>
BufferType<T>::BufferType(T *data, const size_t offset, const size_t size, const size_t capacity)
    : ConstBufferType<T>(data, offset, size, capacity)
{
}

template <typename T, typename R>
class BufferAllocatedType : public BufferType<T>, public RC<R>
{
  private:
    // allow access to other.data_
    template <typename, typename>
    friend class BufferAllocatedType;

    using BufferType<T>::data_;
    using BufferType<T>::offset_;
    using BufferType<T>::size_;
    using BufferType<T>::capacity_;

  public:
    using BufferType<T>::init_headroom;
    using BufferType<T>::buffer_full_error;
    using BufferType<T>::size;
    using BufferType<T>::capacity;
    using BufferType<T>::offset;
    using BufferType<T>::data_raw;
    using BufferType<T>::c_data_raw;
    using BufferType<T>::data;
    using BufferType<T>::c_data;
    using BufferType<T>::operator[];

    enum
    {
        CONSTRUCT_ZERO = (1 << 0), // if enabled, constructors/init will zero allocated space
        DESTRUCT_ZERO = (1 << 1),  // if enabled, destructor will zero data before deletion
        GROW = (1 << 2),           // if enabled, buffer will grow (otherwise buffer_full exception will be thrown)
        ARRAY = (1 << 3),          // if enabled, use as array
    };

    BufferAllocatedType();
    BufferAllocatedType(const size_t capacity, const unsigned int flags);
    BufferAllocatedType(const T *data, const size_t size, const unsigned int flags);
    BufferAllocatedType(const BufferAllocatedType &other);
    template <typename T_>
    BufferAllocatedType(const BufferType<T_> &other, const unsigned int flags);
    void operator=(const BufferAllocatedType &other);
    void init(const size_t capacity, const unsigned int flags);
    void init(const T *data, const size_t size, const unsigned int flags);
    void realloc(const size_t newcap);
    void reset(const size_t min_capacity, const unsigned int flags);
    void reset(const size_t headroom, const size_t min_capacity, const unsigned int flags);
    template <typename T_, typename R_>
    void move(BufferAllocatedType<T_, R_> &other);
    RCPtr<BufferAllocatedType<T, R>> move_to_ptr();
    void swap(BufferAllocatedType &other);
    template <typename T_, typename R_>
    BufferAllocatedType(BufferAllocatedType<T_, R_> &&other) noexcept;
    BufferAllocatedType &operator=(BufferAllocatedType &&other) noexcept;
    void clear();
    void or_flags(const unsigned int flags);
    void and_flags(const unsigned int flags);
    ~BufferAllocatedType();

  protected:
    virtual void reset_impl(const size_t min_capacity, const unsigned int flags);
    virtual void resize(const size_t new_capacity);
    void realloc_(const size_t newcap);
    template <typename T_, typename R_>
    void move_(BufferAllocatedType<T_, R_> &other);
    void erase_();
    void delete_();

    unsigned int flags_;
};

// Member function definitions

template <typename T, typename R>
BufferAllocatedType<T, R>::BufferAllocatedType()
{
    static_assert(std::is_nothrow_move_constructible<BufferAllocatedType>::value, "class BufferAllocatedType not noexcept move constructable");
    flags_ = 0;
}

template <typename T, typename R>
BufferAllocatedType<T, R>::BufferAllocatedType(const size_t capacity, const unsigned int flags)
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

template <typename T, typename R>
BufferAllocatedType<T, R>::BufferAllocatedType(const T *data, const size_t size, const unsigned int flags)
{
    flags_ = flags;
    size_ = capacity_ = size;
    if (size)
    {
        data_ = new T[size];
        std::memcpy(data_, data, size * sizeof(T));
    }
}

template <typename T, typename R>
BufferAllocatedType<T, R>::BufferAllocatedType(const BufferAllocatedType &other)
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

template <typename T, typename R>
template <typename T_>
BufferAllocatedType<T, R>::BufferAllocatedType(const BufferType<T_> &other, const unsigned int flags)
{
    static_assert(sizeof(T) == sizeof(T_), "size inconsistency");
    offset_ = other.offset_;
    size_ = other.size_;
    capacity_ = other.capacity_;
    flags_ = flags;
    if (capacity_)
    {
        data_ = new T[capacity_];
        if (size_)
            std::memcpy(data_ + offset_, other.data_ + offset_, size_ * sizeof(T));
    }
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::operator=(const BufferAllocatedType &other)
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

template <typename T, typename R>
void BufferAllocatedType<T, R>::init(const size_t capacity, const unsigned int flags)
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

template <typename T, typename R>
void BufferAllocatedType<T, R>::init(const T *data, const size_t size, const unsigned int flags)
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

template <typename T, typename R>
void BufferAllocatedType<T, R>::realloc(const size_t newcap)
{
    if (newcap > capacity_)
        realloc_(newcap);
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::reset(const size_t min_capacity, const unsigned int flags)
{
    if (min_capacity > capacity_)
        init(min_capacity, flags);
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::reset(const size_t headroom, const size_t min_capacity, const unsigned int flags)
{
    reset(min_capacity, flags);
    init_headroom(headroom);
}

template <typename T, typename R>
template <typename T_, typename R_>
void BufferAllocatedType<T, R>::move(BufferAllocatedType<T_, R_> &other)
{
    if (data_)
        delete_();
    move_(other);
}

template <typename T, typename R>
RCPtr<BufferAllocatedType<T, R>> BufferAllocatedType<T, R>::move_to_ptr()
{
    RCPtr<BufferAllocatedType<T, R>> bp = new BufferAllocatedType<T, R>();
    bp->move(*this);
    return bp;
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::swap(BufferAllocatedType &other)
{
    std::swap(data_, other.data_);
    std::swap(offset_, other.offset_);
    std::swap(size_, other.size_);
    std::swap(capacity_, other.capacity_);
    std::swap(flags_, other.flags_);
}

template <typename T, typename R>
template <typename T_, typename R_>
BufferAllocatedType<T, R>::BufferAllocatedType(BufferAllocatedType<T_, R_> &&other) noexcept
{
    move_(other);
}

template <typename T, typename R>
BufferAllocatedType<T, R> &BufferAllocatedType<T, R>::operator=(BufferAllocatedType &&other) noexcept
{
    move(other);
    return *this;
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::clear()
{
    erase_();
    flags_ = 0;
    size_ = offset_ = 0;
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::or_flags(const unsigned int flags)
{
    flags_ |= flags;
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::and_flags(const unsigned int flags)
{
    flags_ &= flags;
}

template <typename T, typename R>
BufferAllocatedType<T, R>::~BufferAllocatedType()
{
    if (data_)
        delete_();
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::reset_impl(const size_t min_capacity, const unsigned int flags)
{
    init(min_capacity, flags);
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::resize(const size_t new_capacity)
{
    const size_t newcap = std::max(new_capacity, capacity_ * 2);
    if (newcap > capacity_)
    {
        if (flags_ & GROW)
            realloc_(newcap);
        else
            buffer_full_error(newcap, true);
    }
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::realloc_(const size_t newcap)
{
    T *data = new T[newcap];
    if (size_)
        std::memcpy(data + offset_, data_ + offset_, size_ * sizeof(T));
    delete_();
    data_ = data;
    // std::cout << "*** RESIZE " << capacity_ << " -> " << newcap << std::endl; // fixme
    capacity_ = newcap;
}

template <typename T, typename R>
template <typename T_, typename R_>
void BufferAllocatedType<T, R>::move_(BufferAllocatedType<T_, R_> &other)
{
    data_ = other.data_;
    offset_ = other.offset_;
    size_ = other.size_;
    capacity_ = other.capacity_;
    flags_ = other.flags_;

    other.data_ = nullptr;
    other.offset_ = other.size_ = other.capacity_ = 0;
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::erase_()
{
    if (data_)
    {
        delete_();
        data_ = nullptr;
    }
    capacity_ = 0;
}

template <typename T, typename R>
void BufferAllocatedType<T, R>::delete_()
{
    if (size_ && (flags_ & DESTRUCT_ZERO))
        std::memset(data_, 0, capacity_ * sizeof(T));
    delete[] data_;
}


// specializations of BufferType for unsigned char
typedef BufferType<unsigned char> Buffer;
typedef ConstBufferType<unsigned char> ConstBuffer;
typedef BufferAllocatedType<unsigned char, thread_unsafe_refcount> BufferAllocated;
typedef RCPtr<BufferAllocated> BufferPtr;

// BufferAllocated with thread-safe refcount
typedef BufferAllocatedType<unsigned char, thread_safe_refcount> BufferAllocatedTS;
typedef RCPtr<BufferAllocatedTS> BufferPtrTS;

// cast BufferType<T> to ConstBufferType<T>

template <typename T>
inline ConstBufferType<T> &const_buffer_ref(BufferType<T> &src)
{
    return src;
}

template <typename T>
inline const ConstBufferType<T> &const_buffer_ref(const BufferType<T> &src)
{
    return src;
}

} // namespace openvpn
