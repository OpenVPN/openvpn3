#ifndef OPENVPN_PKI_EPKIBASE_H
#define OPENVPN_PKI_EPKIBASE_H

#include <string>

namespace openvpn {

  class ExternalPKIBase
  {
  public:
    // Sign data (base64) and return signature as sig (base64).
    // Return true on success or false on error.
    virtual bool sign(const std::string& data, std::string& sig) = 0;
  };
}

#endif
