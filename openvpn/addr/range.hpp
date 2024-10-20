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

#include <cstddef> // for std::size_t
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
    class Iterator
    {
        friend class RangeType;

      public:
        bool more() const
        {
            return remaining_ > 0;
        }

        const ADDR &addr() const
        {
            return addr_;
        }

        void next()
        {
            if (more())
            {
                ++addr_;
                --remaining_;
            }
        }

        Iterator &operator++()
        {
            next();
            return *this;
        }

        const ADDR &operator*() const
        {
            return addr_;
        }

        bool operator!=(const Iterator &rhs) const
        {
            return remaining_ != rhs.remaining_ || addr_ != rhs.addr_;
        }

      private:
        Iterator(const RangeType &range)
            : addr_(range.start_), remaining_(range.extent_)
        {
        }

        ADDR addr_;
        std::size_t remaining_;
    };

    RangeType()
        : extent_(0)
    {
    }

    RangeType(const ADDR &start, const std::size_t extent)
        : start_(start), extent_(extent)
    {
    }

    Iterator begin() const
    {
        return Iterator(*this);
    }

    Iterator end() const
    {
        RangeType end_range = *this;
        end_range.start_ += static_cast<long>(end_range.extent_);
        end_range.extent_ = 0;
        return Iterator(end_range);
    }

    Iterator iterator() const
    {
        return Iterator(*this);
    }

    bool defined() const
    {
        return extent_ > 0;
    }

    const ADDR &start() const
    {
        return start_;
    }

    std::size_t extent() const
    {
        return extent_;
    }

    RangeType pull_front(std::size_t extent)
    {
        if (extent > extent_)
            extent = extent_;
        RangeType ret(start_, extent);
        start_ += extent;
        extent_ -= extent;
        return ret;
    }

    std::string to_string() const
    {
        std::ostringstream os;
        os << start_.to_string() << '[' << extent_ << ']';
        return os.str();
    }

  private:
    ADDR start_;
    std::size_t extent_;
};

template <typename ADDR>
class RangePartitionType
{
  public:
    RangePartitionType(const RangeType<ADDR> &src_range, const std::size_t n_partitions)
        : range(src_range),
          remaining(n_partitions)
    {
    }

    bool next(RangeType<ADDR> &r)
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

  private:
    RangeType<ADDR> range;
    std::size_t remaining;
};

typedef RangeType<IP::Addr> Range;
typedef RangePartitionType<IP::Addr> RangePartition;
} // namespace openvpn::IP

#endif
