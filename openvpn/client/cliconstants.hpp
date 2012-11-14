//
//  cliconstants.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_CLIENT_CLICONSTANTS_H
#define OPENVPN_CLIENT_CLICONSTANTS_H

namespace openvpn {
  namespace ProfileParseLimits {
    enum {
      MAX_PROFILE_SIZE=262144,
      MAX_PUSH_SIZE=65536,
      MAX_LINE_SIZE=512,
      MAX_DIRECTIVE_SIZE=64,
      OPT_OVERHEAD=64,    // bytes overhead of one option, for accounting purposes
      TERM_OVERHEAD=16,   // bytes overhead of one argument in an option, for accounting purposes
    };
  }
}

#endif
