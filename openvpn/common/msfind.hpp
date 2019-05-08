//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2019 OpenVPN Inc.
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


// map/set find

#pragma once

#include <utility>

namespace openvpn {
  namespace MSF {

    template <typename MAP_SET, typename ITERATOR>
    class Iter : public ITERATOR
    {
    public:
      Iter(const MAP_SET& ms, ITERATOR&& iter)
	: ITERATOR(std::move(iter)),
	  exists_(*this != ms.end())
      {
      }

      explicit operator bool() const
      {
	return exists_;
      }

    private:
      bool exists_;
    };

    // Like ordinary map/set find, but returns an iterator
    // that defines an operator bool() method for testing if
    // the iterator is defined, i.e. iter != map_or_set.end()
    template <typename MAP_SET, typename KEY>
    inline auto find(MAP_SET& ms, const KEY& k)
    {
      return Iter<MAP_SET, decltype(ms.find(k))>(ms, ms.find(k));
    }
  }
}
