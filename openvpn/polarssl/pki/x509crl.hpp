//
//  x509crl.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// Wrap a PolarSSL x509_crl object

#ifndef OPENVPN_POLARSSL_PKI_X509CRL_H
#define OPENVPN_POLARSSL_PKI_X509CRL_H

#include <string>
#include <sstream>
#include <cstring>

#include <polarssl/x509_crl.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/polarssl/util/error.hpp>

namespace openvpn {
  namespace PolarSSLPKI {

    class X509CRL : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<X509CRL> Ptr;

      X509CRL() : chain(NULL) {}

      X509CRL(const std::string& crl_txt)
	: chain(NULL)
      {
	try {
	  parse(crl_txt);
	}
	catch (...)
	  {
	    dealloc();
	    throw;
	  }
      }

      void parse(const std::string& crl_txt)
      {
	alloc();

	const int status = x509_crl_parse(chain,
					  (const unsigned char *)crl_txt.c_str(),
					  crl_txt.length());
	if (status < 0)
	  {
	    throw PolarSSLException("error parsing CRL", status);
	  }
      }

      x509_crl* get() const
      {
	return chain;
      }

      ~X509CRL()
      {
	dealloc();
      }

    private:
      void alloc()
      {
	if (!chain)
	  {
	    chain = new x509_crl;
	    std::memset(chain, 0, sizeof(x509_crl));
	  }
      }

      void dealloc()
      {
	if (chain)
	  {
	    x509_crl_free(chain);
	    delete chain;
	    chain = NULL;
	  }
      }

      x509_crl *chain;
    };
  }
}

#endif
