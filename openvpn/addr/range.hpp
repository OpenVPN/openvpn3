//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

#ifndef OPENVPN_ADDR_RANGE_H
#define OPENVPN_ADDR_RANGE_H

#include <cstddef>
#include <string>
#include <sstream>

#include <openvpn/addr/ip.hpp>

namespace openvpn::IP {

// Denote a range of IP addresses with a start and extent,
// where A represents an address class.
// A should be a network address class such as IP::Addr, IPv4::Addr, or IPv6::Addr.

template <typename ADDR>
class RangeType
{
  public:
    class Iterator;

    RangeType();
    RangeType(const ADDR &start, const std::size_t extent);
    Iterator begin() const;
    Iterator end() const;
    Iterator iterator() const;
    bool defined() const;
    const ADDR &start() const;
    std::size_t extent() const;
    RangeType pull_front(std::size_t extent);
    std::string to_string() const;

  private:
    ADDR start_;
    std::size_t extent_;
};

template <typename ADDR>
class RangeType<ADDR>::Iterator
{
    friend class RangeType;

  public:
    bool more() const;
    const ADDR &addr() const;
    void next();
    Iterator &operator++();
    const ADDR &operator*() const;
    bool operator!=(const Iterator &rhs) const;

  private:
    Iterator(const RangeType &range)
        : addr_(range.start_), remaining_(range.extent_)
    {
    }

    ADDR addr_;
    std::size_t remaining_;
};

using Range = RangeType<IP::Addr>;

template <typename ADDR>
class RangePartitionType
{
  public:
    RangePartitionType(const RangeType<ADDR> &src_range, const std::size_t n_partitions);
    bool next(RangeType<ADDR> &r);

  private:
    RangeType<ADDR> range;
    std::size_t remaining;
};

using RangePartition = RangePartitionType<IP::Addr>;

// ================================================================================================

template <typename ADDR>
inline bool RangeType<ADDR>::Iterator::more() const
{
    return remaining_ > 0;
}

template <typename ADDR>
inline const ADDR &RangeType<ADDR>::Iterator::addr() const
{
    return addr_;
}

template <typename ADDR>
inline void RangeType<ADDR>::Iterator::next()
{
    if (more())
    {
        ++addr_;
        --remaining_;
    }
}

template <typename ADDR>
inline typename RangeType<ADDR>::Iterator &RangeType<ADDR>::Iterator::operator++()
{
    next();
    return *this;
}

template <typename ADDR>
inline const ADDR &RangeType<ADDR>::Iterator::operator*() const
{
    return addr_;
}

template <typename ADDR>
inline bool RangeType<ADDR>::Iterator::operator!=(const Iterator &rhs) const
{
    return remaining_ != rhs.remaining_ || addr_ != rhs.addr_;
}

template <typename ADDR>
inline RangeType<ADDR>::RangeType()
    : extent_(0)
{
}

template <typename ADDR>
inline RangeType<ADDR>::RangeType(const ADDR &start, const std::size_t extent)
    : start_(start), extent_(extent)
{
}

template <typename ADDR>
inline typename RangeType<ADDR>::Iterator RangeType<ADDR>::begin() const
{
    return Iterator(*this);
}

template <typename ADDR>
inline typename RangeType<ADDR>::Iterator RangeType<ADDR>::end() const
{
    RangeType end_range = *this;
    end_range.start_ += static_cast<long>(end_range.extent_);
    end_range.extent_ = 0;
    return Iterator(end_range);
}

template <typename ADDR>
inline typename RangeType<ADDR>::Iterator RangeType<ADDR>::iterator() const
{
    return Iterator(*this);
}

template <typename ADDR>
inline bool RangeType<ADDR>::defined() const
{
    return extent_ > 0;
}

template <typename ADDR>
inline const ADDR &RangeType<ADDR>::start() const
{
    return start_;
}

template <typename ADDR>
inline std::size_t RangeType<ADDR>::extent() const
{
    return extent_;
}

template <typename ADDR>
inline RangeType<ADDR> RangeType<ADDR>::pull_front(std::size_t extent)
{
    if (extent > extent_)
        extent = extent_;
    RangeType ret(start_, extent);
    start_ += extent;
    extent_ -= extent;
    return ret;
}

template <typename ADDR>
inline std::string RangeType<ADDR>::to_string() const
{
    std::ostringstream os;
    os << start_.to_string() << '[' << extent_ << ']';
    return os.str();
}

template <typename ADDR>
inline RangePartitionType<ADDR>::RangePartitionType(const RangeType<ADDR> &src_range, const std::size_t n_partitions)
    : range(src_range),
      remaining(n_partitions)
{
}

template <typename ADDR>
inline bool RangePartitionType<ADDR>::next(RangeType<ADDR> &r)
{
    if (remaining)
    {
        if (remaining > 1)
            r = range.pull_front(range.extent() / remaining);
        else
            r = range;
        --remaining;
        return r.defined();
    }
    else
        return false;
}

} // namespace openvpn::IP

#endif
