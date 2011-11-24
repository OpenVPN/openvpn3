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

    enum Flags {
      DEBUG = 1<<0,
    };

    SSLConfig() : mode(UNDEF), flags(0) {}

    Mode mode;
    unsigned int flags;
    std::string ca;
    std::string cert;
    std::string extra_certs;
    std::string pkey;
    std::string dh;
    FramePtr frame;
  };

} // namespace openvpn

#endif // OPENVPN_SSL_SSLCONF_H
