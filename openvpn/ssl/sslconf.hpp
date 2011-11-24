#ifndef OPENVPN_SSL_SSLCONF_H
#define OPENVPN_SSL_SSLCONF_H

#include <string>

namespace openvpn {

  struct SSLConfig
  {
    enum Mode {
      UNDEF,
      CLIENT,
      SERVER
    };

    SSLConfig() : mode(UNDEF) {}

    Mode mode;
    std::string ca;
    std::string cert;
    std::string extra_certs;
    std::string pkey;
    std::string dh;
  };

} // namespace openvpn

#endif // OPENVPN_SSL_SSLCONF_H
