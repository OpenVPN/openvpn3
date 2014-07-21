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

// A scoped Asio stream that is automatically closed by its destructor.

#ifndef OPENVPN_COMMON_SCOPED_ASIO_STREAM_H
#define OPENVPN_COMMON_SCOPED_ASIO_STREAM_H

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>

namespace openvpn {

  template <typename STREAM>
  class ScopedAsioStream : boost::noncopyable
  {
  public:
    typedef STREAM* base_type;

    ScopedAsioStream() : obj_(undefined()) {}

    explicit ScopedAsioStream(STREAM *obj)
      : obj_(obj) {}

    static STREAM* undefined() { return NULL; }

    STREAM* release()
    {
      STREAM* ret = obj_;
      obj_ = NULL;
      //OPENVPN_LOG("**** SAS RELEASE=" << ret);
      return ret;
    }

    static bool defined_static(STREAM* obj)
    {
      return obj != NULL;
    }

    bool defined() const
    {
      return defined_static(obj_);
    }

    STREAM* operator()() const
    {
      return obj_;
    }

    void reset(STREAM* obj)
    {
      close();
      obj_ = obj;
      //OPENVPN_LOG("**** SAS RESET=" << obj_);
    }

    // unusual semantics: replace obj without closing it first
    void replace(STREAM* obj)
    {
      //OPENVPN_LOG("**** SAS REPLACE " << obj_ << " -> " << obj);
      obj_ = obj;
    }

    // return false if close error
    bool close()
    {
      if (defined())
	{
	  //OPENVPN_LOG("**** SAS CLOSE obj=" << obj_);
	  delete obj_;
	  obj_ = NULL;
	}
      return true;
    }

    ~ScopedAsioStream()
    {
      //OPENVPN_LOG("**** SAS DESTRUCTOR");
      close();
    }

  private:
    STREAM* obj_;
  };

} // namespace openvpn

#endif
