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

#ifndef OPENVPN_ADDR_RANGE_H
#define OPENVPN_ADDR_RANGE_H

#include <string>
#include <sstream>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {
  namespace IP {

    // Denote a range of IP addresses with a start and extent,
    // where A represents an address class.
    // A should be a network address class such as IP::Addr, IPv4::Addr, or IPv6::Addr.

    template <typename A>
    class Range
    {
    public:
      class Iterator
      {
	friend class Range;
      public:
	bool more() const { return remaining_ > 0; }

	const A& addr() const { return addr_; }

	void next()
	{
	  if (more())
	    {
	      ++addr_;
	      --remaining_;
	    }
	}

      private:
	Iterator(const Range& range)
	  : addr_(range.start_), remaining_(range.extent_) {}

	A addr_;
	size_t remaining_;
      };

      Range() : extent_(0) {}

      Range(const A& start, const size_t extent)
	: start_(start), extent_(extent) {}

      Iterator iterator() const { return Iterator(*this); }

      std::string to_string() const
      {
	std::ostringstream os;
	os << start_.to_string() << '[' << extent_ << ']';
	return os.str();
      }

    private:
      A start_;
      size_t extent_;
    };
  }
}

#endif
