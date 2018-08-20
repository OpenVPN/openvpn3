//
//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc. All rights reserved.
//

// AWS API CA

#pragma once

#include <openvpn/common/fileunix.hpp>

namespace openvpn {
  namespace AWS {
    inline std::string api_ca()
    {
      return read_text_unix("/etc/ssl/certs/ca-certificates.crt");
    }
  }
}
