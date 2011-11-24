#ifndef OPENVPN_GENCRYPTO_GENSSLCTX_H
#define OPENVPN_GENCRYPTO_GENSSLCTX_H

#include <openvpn/gencrypto/gencrypto.hpp>
#ifdef OPENVPN_APPLE_CRYPTO
#error SSL not implemented yet for Apple
#else
#include <openvpn/openssl/ssl/sslctx.hpp>
#endif

namespace openvpn {
#ifdef OPENVPN_APPLE_CRYPTO
#error SSL not implemented yet for Apple
#else
  typedef OpenSSLContext SSLContext;
  typedef OpenSSLContextPtr SSLContextPtr;
#endif
} // namespace openvpn

#endif // OPENVPN_GENCRYPTO_GENSSLCTX_H
