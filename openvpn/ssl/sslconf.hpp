#ifndef OPENVPN_SSL_SSLCONF_H
#define OPENVPN_SSL_SSLCONF_H

#include <string>

#include <openvpn/frame/frame.hpp>

namespace openvpn {

  struct SSLConfig
  {
    enum Mode {
      UNDEF,
      CLIENT,
      SERVER
    };

    enum {
      DEBUG = 1<<0,
    };
    typedef unsigned int Flags;

    SSLConfig() : mode(UNDEF), flags(0) {}

    Mode mode;
    Flags flags;

    // If defined, look up ca, cert, and pkey in cert store,
    // by matching against X509 subject.
    std::string identity;

    std::string ca;
    std::string cert;
    std::string extra_certs;
    std::string pkey;
    std::string dh; // only needed by server
    FramePtr frame;
  };

} // namespace openvpn

#endif // OPENVPN_SSL_SSLCONF_H
