//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2013-2014 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// define a TARGET_x macro that describes our build target

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
