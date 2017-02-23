//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2016 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// Wrap a mbed TLS pk_context object.

#ifndef OPENVPN_MBEDTLS_PKI_PKCTX_H
#define OPENVPN_MBEDTLS_PKI_PKCTX_H

#include <string>
#include <sstream>
#include <cstring>

#include <mbedtls/pk.h>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/polarssl/util/error.hpp>

namespace openvpn {
  namespace PolarSSLPKI {

    class PKContext : public RC<thread_unsafe_refcount>
    {
    public:
      typedef RCPtr<PKContext> Ptr;

      PKContext() : ctx(nullptr) {}

      PKContext(const std::string& key_txt, const std::string& title, const std::string& priv_key_pwd)
	: ctx(nullptr)
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

      bool defined() const
      {
	return ctx != nullptr;
      }

      void parse(const std::string& key_txt, const std::string& title, const std::string& priv_key_pwd)
      {
	alloc();
	// key_txt.length() is increased by 1 as it does not include the NULL-terminator
	// which mbedtls_pk_parse_key() expects to see.
	const int status = mbedtls_pk_parse_key(ctx,
					(const unsigned char *)key_txt.c_str(),
					key_txt.length() + 1,
					(const unsigned char *)priv_key_pwd.c_str(),
					priv_key_pwd.length());
	if (status < 0)
	  throw PolarSSLException("error parsing " + title + " private key", status);
      }

      void epki_enable(void *arg,
		       mbedtls_pk_rsa_alt_decrypt_func epki_decrypt,
		       mbedtls_pk_rsa_alt_sign_func epki_sign,
		       mbedtls_pk_rsa_alt_key_len_func epki_key_len)
      {
	alloc();
	const int status = mbedtls_pk_setup_rsa_alt(ctx, arg, epki_decrypt, epki_sign, epki_key_len);
	if (status < 0)
	  throw PolarSSLException("error in mbedtls_pk_setup_rsa_alt", status);
      }

      mbedtls_pk_context* get() const
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
	    ctx = new mbedtls_pk_context;
	    mbedtls_pk_init(ctx);
	  }
      }

      void dealloc()
      {
	if (ctx)
	  {
	    mbedtls_pk_free(ctx);
	    delete ctx;
	    ctx = nullptr;
	  }
      }

      mbedtls_pk_context *ctx;
    };

  }
}
#endif
