//
//  platform.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_COMMON_PLATFORM_H
#define OPENVPN_COMMON_PLATFORM_H

#if defined(_WIN32)
# define OPENVPN_PLATFORM_WIN
#elif defined(__APPLE__)
# include "TargetConditionals.h"
# define OPENVPN_PLATFORM_TYPE_APPLE
# if TARGET_OS_IPHONE // includes iPad
#  define OPENVPN_PLATFORM_IPHONE
#  define OPENVPN_PLATFORM_IPHONE_DEVICE
# elif TARGET_IPHONE_SIMULATOR // includes iPad
#  define OPENVPN_PLATFORM_IPHONE
#  define OPENVPN_PLATFORM_IPHONE_SIMULATOR
# elif TARGET_OS_MAC
#  define OPENVPN_PLATFORM_MAC
# endif
#elif defined(__ANDROID__)
# define OPENVPN_PLATFORM_ANDROID
#elif defined(__linux__)
# define OPENVPN_PLATFORM_LINUX
#endif

#if !defined(_WIN32)
#define OPENVPN_PLATFORM_TYPE_UNIX
#endif

#endif // OPENVPN_COMMON_PLATFORM_H
