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

// A low-level backward reference object.

#ifndef OPENVPN_COMMON_BACKREF_H
#define OPENVPN_COMMON_BACKREF_H

namespace openvpn {

  template <typename REF>
  class BackRef {
  public:
    BackRef() { reset(); }

    bool defined() const
    {
      return ref_ != NULL;
    }

    void reset()
    {
      ref_ = NULL;
      value_ = NULL;
    }

    void set(REF* ref, void* value)
    {
      ref_ = ref;
      value_ = value;
    }

    void set_ref(REF* ref)
    {
      ref_ = ref;
    }

    void set_value(void* value)
    {
      value_ = value;
    }

    template <typename VALUE>
    VALUE* value() const
    {
      return (VALUE*)value_;
    }

    REF* ref() const { return ref_; }

  private:
    REF* ref_;
    void* value_;
  };

}

#endif
