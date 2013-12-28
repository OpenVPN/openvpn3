//
//  likely.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_LIKELY_H
#define OPENVPN_COMMON_LIKELY_H

// Branch prediction hints (these make a difference on ARM)
#if !defined(likely) && !defined(unlikely)
#if defined(__GNUC__)
# define likely(x)    __builtin_expect((x),1)
# define unlikely(x)  __builtin_expect((x),0)
#else
# define likely(x)    (x)
# define unlikely(x)  (x)
#endif
#endif

#endif // OPENVPN_COMMON_LIKELY_H
