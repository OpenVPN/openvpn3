//
//  stringize.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_STRINGIZE_H
#define OPENVPN_COMMON_STRINGIZE_H

// OPENVPN_STRINGIZE(x) -- put double-quotes around x

#define OPENVPN_STRINGIZE(x) OPENVPN_STRINGIZE2(x)
#define OPENVPN_STRINGIZE2(x) #x

#endif
