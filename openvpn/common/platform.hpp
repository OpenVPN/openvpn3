#ifndef OPENVPN_COMMON_PLATFORM_H
#define OPENVPN_COMMON_PLATFORM_H

#if defined(_WIN32)
# define OPENVPN_PLATFORM_WIN
#elif defined(__APPLE__)
# include "TargetConditionals.h"
# define OPENVPN_PLATFORM_TYPE_APPLE
# if TARGET_OS_IPHONE
#  define OPENVPN_PLATFORM_IPHONE
# elif TARGET_IPHONE_SIMULATOR
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
