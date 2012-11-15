//
//  rsactx.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_POLARSSL_PKI_RSACTX_H
#define OPENVPN_POLARSSL_PKI_RSACTX_H

#include <string>
#include <sstream>
#include <cstring>

#include <polarssl/x509.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/polarssl/util/error.hpp>

namespace openvpn {
  namespace PolarSSLPKI {

    class RSAContext : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<RSAContext> Ptr;

      RSAContext() : ctx(NULL) {}

      RSAContext(const std::string& key_txt, const std::string& title, const std::string& priv_key_pwd)
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
	const int status = x509parse_key(ctx,
					 (const unsigned char *)key_txt.c_str(),
					 key_txt.length(),
					 (const unsigned char *)priv_key_pwd.c_str(),
					 priv_key_pwd.length());
	if (status < 0)
	  throw PolarSSLException("error parsing " + title + " private key", status);
      }

      rsa_context* get() const
      {
	return ctx;
      }

      ~RSAContext()
      {
	dealloc();
      }

    private:
      void alloc()
      {
	if (!ctx)
	  {
	    ctx = new rsa_context;
	    std::memset(ctx, 0, sizeof(rsa_context));
	  }
      }

      void dealloc()
      {
	if (ctx)
	  {
	    rsa_free(ctx);
	    delete ctx;
	    ctx = NULL;
	  }
      }

      rsa_context *ctx;
    };

  }
}
#endif
