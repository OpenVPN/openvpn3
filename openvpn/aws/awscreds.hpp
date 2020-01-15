//
//  OpenVPN
//
//  Copyright (C) 2012-2017 OpenVPN Technologies, Inc. All rights reserved.
//

// AWS credentials

#pragma once

#include <string>

namespace openvpn {
  namespace AWS {
    struct Creds
    {
      Creds() {}

      Creds(std::string access_key_arg,
	    std::string secret_key_arg,
	    std::string token_arg = "")
	: access_key(std::move(access_key_arg)),
	  secret_key(std::move(secret_key_arg)),
	  token(std::move(token_arg))
      {
      }

      bool defined() const
      {
	return !access_key.empty() && !secret_key.empty();
      }

      std::string to_string() const
      {
	return "AWS::Creds[access_key=" + access_key + " len(secret_key)=" + std::to_string(secret_key.length()) + ']';
      }

      std::string access_key;
      std::string secret_key;
      std::string token;
    };
  }
}
