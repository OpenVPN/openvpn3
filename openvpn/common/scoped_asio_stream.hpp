//
//  scoped_asio_stream.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

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
