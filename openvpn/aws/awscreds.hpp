//
//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc. All rights reserved.
//

// AWS credentials

#ifndef OPENVPN_AWS_AWSCREDS_H
#define OPENVPN_AWS_AWSCREDS_H

#include <string>

namespace openvpn {
  namespace AWS {
    struct Creds
    {
      Creds() {}

      Creds(std::string access_key_arg,
	    std::string secret_key_arg)
	: access_key(std::move(access_key_arg)),
	  secret_key(std::move(secret_key_arg))
      {
      }

      std::string access_key;
      std::string secret_key;
    };
  }
}

#endif
