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
	const int status = x509parse_crt(chain,
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
	    throw PolarSSLException(os.str());
	  }
      }

      x509_cert* get() const
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
	    chain = new x509_cert;
	    std::memset(chain, 0, sizeof(x509_cert));
	  }
      }

      void dealloc()
      {
	if (chain)
	  {
	    x509_free(chain);
	    delete chain;
	    chain = NULL;
	  }
      }

      x509_cert *chain;
    };
  }
}

#endif
