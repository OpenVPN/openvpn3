//
//  cliconstants.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_CLIENT_CLICONSTANTS_H
#define OPENVPN_CLIENT_CLICONSTANTS_H

// Various sanity checks for different limits on OpenVPN clients

namespace openvpn {
  namespace ProfileParseLimits {
    enum {
      MAX_PROFILE_SIZE=262144, // maximum size of an OpenVPN configuration file
      MAX_PUSH_SIZE=65536,     // maximum size of aggregate data that can be pushed to a client
      MAX_LINE_SIZE=512,       // maximum size of an OpenVPN configuration file line
      MAX_DIRECTIVE_SIZE=64,   // maximum number of chars in an OpenVPN directive
      OPT_OVERHEAD=64,         // bytes overhead of one option/directive, for accounting purposes
      TERM_OVERHEAD=16,        // bytes overhead of one argument in an option, for accounting purposes
    };
  }
}

#endif
