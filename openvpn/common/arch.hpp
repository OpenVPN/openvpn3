//
//  arch.hpp
//  OpenVPN
//
//  Copyright (c) 2014 OpenVPN Technologies, Inc. All rights reserved.
//

// define an ARCH_x macro that describes our target architecture

#ifndef OPENVPN_COMMON_ARCH_H
#define OPENVPN_COMMON_ARCH_H

#if defined(__amd64__) || defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64)
# define OPENVPN_ARCH_x86_64
#elif defined(__i386__) || defined(_M_IX86)
# define OPENVPN_ARCH_i386
#elif defined(__aarch64__) || defined(__arm64__)
# define OPENVPN_ARCH_ARM64
#elif defined(__arm__) || defined(_M_ARM)
# define OPENVPN_ARCH_ARM
#endif

#endif
