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
