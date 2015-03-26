//
//  OpenVPN
//
//  Copyright (C) 2012-2015 OpenVPN Technologies, Inc. All rights reserved.
//

#include <string>

#include <openvpn/common/rc.hpp>
#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/ssl/sslapi.hpp>
#include <openvpn/ssl/sslconsts.hpp>
#include <openvpn/ws/chunked.hpp>

#ifndef OPENVPN_WS_HTTPSERV_H
#define OPENVPN_WS_HTTPSERV_H

namespace openvpn {
  namespace WS {
    namespace Server {

      struct Config : public RC<thread_unsafe_refcount>
      {
	typedef boost::intrusive_ptr<Config> Ptr;

	Config() : general_timeout(0),
		   max_headers(0),
		   max_header_bytes(0),
		   max_content_bytes(0) {}

	SSLFactoryAPI::Ptr ssl_factory;
	unsigned int general_timeout;
	unsigned int max_headers;
	unsigned int max_header_bytes;
	olong max_content_bytes;
	Frame::Ptr frame;
	SessionStats::Ptr stats;
      };

      class RequestHandler
      {
      public:
      protected:
      };

      class RequestHandlerFactory
      {
      public:
      };

      class Listener
      {
      public:
      private:
      };
    }
  }
}

#endif
