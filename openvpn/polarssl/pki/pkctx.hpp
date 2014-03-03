//
//  pkctx.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Wrap a PolarSSL pk_context object.

#ifndef OPENVPN_POLARSSL_PKI_PKCTX_H
#define OPENVPN_POLARSSL_PKI_PKCTX_H

#include <string>
#include <sstream>
#include <cstring>

#include <polarssl/pk.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/polarssl/util/error.hpp>

namespace openvpn {
  namespace PolarSSLPKI {

    class PKContext : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<PKContext> Ptr;

      PKContext() : ctx(NULL) {}

      PKContext(const std::string& key_txt, const std::string& title, const std::string& priv_key_pwd)
	: ctx(NULL)
      {
	try {
	  parse(key_txt, title, priv_key_pwd);
	}
	catch (...)
	  {
	    dealloc();
	    throw;
	  }
      }

      void parse(const std::string& key_txt, const std::string& title, const std::string& priv_key_pwd)
      {
	alloc();
	const int status = pk_parse_key(ctx,
					(const unsigned char *)key_txt.c_str(),
					key_txt.length(),
					(const unsigned char *)priv_key_pwd.c_str(),
					priv_key_pwd.length());
	if (status < 0)
	  throw PolarSSLException("error parsing " + title + " private key", status);
      }

      pk_context* get() const
      {
	return ctx;
      }

      ~PKContext()
      {
	dealloc();
      }

    private:
      void alloc()
      {
	if (!ctx)
	  {
	    ctx = new pk_context;
	    pk_init(ctx);
	  }
      }

      void dealloc()
      {
	if (ctx)
	  {
	    pk_free(ctx);
	    delete ctx;
	    ctx = NULL;
	  }
      }

      pk_context *ctx;
    };

  }
}
#endif
