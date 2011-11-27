#ifndef OPENVPN_APPLECRYPTO_CF_CFSEC_H
#define OPENVPN_APPLECRYPTO_CF_CFSEC_H

#include <Security/SecCertificate.h>
#include <Security/SecIdentity.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/applecrypto/cf/cf.hpp>

namespace openvpn {

  namespace CF {

    // CF types

    typedef CFWrap<SecCertificateRef> Cert;
    typedef CFWrap<SecIdentityRef> Identity;

    // casts

    inline Cert cert_cast(CFTypeRef obj)
    {
      if (obj && CFGetTypeID(obj) == SecCertificateGetTypeID())
	return Cert((SecCertificateRef)obj, BORROW);
      else
	return Cert();
    }

    inline Identity identity_cast(CFTypeRef obj)
    {
      if (obj && CFGetTypeID(obj) == SecIdentityGetTypeID())
	return Identity((SecIdentityRef)obj, BORROW);
      else
	return Identity();
    }

  } // namespace CF

} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_CF_CFSEC_H
