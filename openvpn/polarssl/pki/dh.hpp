//
//  dh.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Wrap a PolarSSL dhm_context object (Diffie Hellman parameters).

#ifndef OPENVPN_POLARSSL_PKI_DH_H
#define OPENVPN_POLARSSL_PKI_DH_H

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

    class DH : public RC<thread_unsafe_refcount>
    {
    public:
      typedef boost::intrusive_ptr<DH> Ptr;

      DH() : dhc(NULL) {}

      DH(const std::string& dh_txt, const std::string& title)
	: dhc(NULL)
      {
	try {
	  parse(dh_txt, title);
	}
	catch (...)
	  {
	    dealloc();
	    throw;
	  }
      }

      void parse(const std::string& dh_txt, const std::string& title)
      {
	alloc();
	const int status = dhm_parse_dhm(dhc,
					 (const unsigned char *)dh_txt.c_str(),
					 dh_txt.length());
	if (status < 0)
	  {
	    throw PolarSSLException("error parsing " + title + " DH parameters", status);
	  }
	if (status > 0)
	  {
	    std::ostringstream os;
	    os << status << " DH parameters in " << title << " failed to parse";
	    throw PolarSSLException(os.str());
	  }
      }

      dhm_context* get() const
      {
	return dhc;
      }

      ~DH()
      {
	dealloc();
      }

    private:
      void alloc()
      {
	if (!dhc)
	  {
	    dhc = new dhm_context;
	    //std::memset(dhc, 0, sizeof(dhm_context)); // not needed because x509parse_dhm does this
	  }
      }

      void dealloc()
      {
	if (dhc)
	  {
	    dhm_free(dhc);
	    delete dhc;
	    dhc = NULL;
	  }
      }

      dhm_context *dhc;
    };
  }
}

#endif
