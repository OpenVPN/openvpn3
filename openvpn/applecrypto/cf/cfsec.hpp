#ifndef OPENVPN_APPLECRYPTO_CF_CFSEC_H
#define OPENVPN_APPLECRYPTO_CF_CFSEC_H

#include <Security/SecCertificate.h>
#include <Security/SecIdentity.h>
#include <Security/SecKeychain.h>
#include <Security/SecAccess.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/applecrypto/cf/cf.hpp>

namespace openvpn {

  namespace CF {

    OPENVPN_CF_WRAP(Cert, cert_cast, SecCertificateRef, SecCertificateGetTypeID)
    OPENVPN_CF_WRAP(Identity, identity_cast, SecIdentityRef, SecIdentityGetTypeID)
    OPENVPN_CF_WRAP(Keychain, keychain_cast, SecKeychainRef, SecKeychainGetTypeID)
    OPENVPN_CF_WRAP(Access, access_cast, SecAccessRef, SecAccessGetTypeID)

  } // namespace CF

} // namespace openvpn

#endif // OPENVPN_APPLECRYPTO_CF_CFSEC_H
