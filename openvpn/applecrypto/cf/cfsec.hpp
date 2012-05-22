#ifndef OPENVPN_APPLECRYPTO_CF_CFSEC_H
#define OPENVPN_APPLECRYPTO_CF_CFSEC_H

#include <openvpn/common/platform.hpp>

#include <Security/SecCertificate.h>
#include <Security/SecIdentity.h>

#ifndef OPENVPN_PLATFORM_IPHONE
#include <Security/SecKeychain.h>
#include <Security/SecAccess.h>
#endif

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/applecrypto/cf/cf.hpp>

namespace openvpn {
  namespace CF {
    OPENVPN_CF_WRAP(Cert, cert_cast, SecCertificateRef, SecCertificateGetTypeID)
    OPENVPN_CF_WRAP(Identity, identity_cast, SecIdentityRef, SecIdentityGetTypeID)
#ifndef OPENVPN_PLATFORM_IPHONE
    OPENVPN_CF_WRAP(Keychain, keychain_cast, SecKeychainRef, SecKeychainGetTypeID)
    OPENVPN_CF_WRAP(Access, access_cast, SecAccessRef, SecAccessGetTypeID)
#endif
  } // namespace CF

} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_CF_CFSEC_H
