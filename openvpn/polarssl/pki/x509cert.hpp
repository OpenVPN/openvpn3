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

// Wrap a PolarSSL x509_crt object

#ifndef OPENVPN_POLARSSL_PKI_X509CERT_H
#define OPENVPN_POLARSSL_PKI_X509CERT_H

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

    class X509Cert : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<X509Cert> Ptr;

      X509Cert() : chain(NULL) {}

      X509Cert(const std::string& cert_txt, const std::string& title)
	: chain(NULL)
      {
	try {
	  parse(cert_txt, title);
	}
	catch (...)
	  {
	    dealloc();
	    throw;
	  }
      }

      void parse(const std::string& cert_txt, const std::string& title)
      {
	alloc();

	if (cert_txt.empty())
	  throw PolarSSLException(title + " certificate is undefined");

	const int status = x509_crt_parse(chain,
					  (const unsigned char *)cert_txt.c_str(),
					  cert_txt.length());
	if (status < 0)
	  {
	    throw PolarSSLException("error parsing " + title + " certificate", status);
	  }
	if (status > 0)
	  {
	    std::ostringstream os;
	    os << status << " certificate(s) in " << title << " bundle failed to parse";
#if 1 // PolarSSL cert parse error
	    throw PolarSSLException(os.str());
#else
	    OPENVPN_LOG("POLARSSL: " << os.str());
#endif
	  }
      }

      x509_crt* get() const
      {
	return chain;
      }

      ~X509Cert()
      {
	dealloc();
      }

    private:
      void alloc()
      {
	if (!chain)
	  {
	    chain = new x509_crt;
	    std::memset(chain, 0, sizeof(x509_crt));
	  }
      }

      void dealloc()
      {
	if (chain)
	  {
	    x509_crt_free(chain);
	    delete chain;
	    chain = NULL;
	  }
      }

      x509_crt *chain;
    };
  }
}

#endif
