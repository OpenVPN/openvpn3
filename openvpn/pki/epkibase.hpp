//
//  epkibase.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_PKI_EPKIBASE_H
#define OPENVPN_PKI_EPKIBASE_H

#include <string>

namespace openvpn {

  // Abstract base class used to provide an interface where core SSL implementation
  // can use an external private key.
  class ExternalPKIBase
  {
  public:
    // Sign data (base64) and return signature as sig (base64).
    // Return true on success or false on error.
    virtual bool sign(const std::string& sig_type, const std::string& data, std::string& sig) = 0;

    virtual ~ExternalPKIBase() {}
  };
}

#endif
