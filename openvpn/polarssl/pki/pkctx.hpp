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
