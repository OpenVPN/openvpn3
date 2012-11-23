//
//  tunlog.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// Define tun logging macros using OPENVPN_DEBUG_TUN as a verbosity level.

#ifndef OPENVPN_TUN_TUNLOG_H
#define OPENVPN_TUN_TUNLOG_H

#if defined(OPENVPN_DEBUG_TUN) && OPENVPN_DEBUG_TUN >= 1
#define OPENVPN_LOG_TUN_ERROR(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_TUN_ERROR(x)
#endif

#if defined(OPENVPN_DEBUG_TUN) && OPENVPN_DEBUG_TUN >= 2
#define OPENVPN_LOG_TUN(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_TUN(x)
#endif

#if defined(OPENVPN_DEBUG_TUN) && OPENVPN_DEBUG_TUN >= 3
#define OPENVPN_LOG_TUN_VERBOSE(x) OPENVPN_LOG(x)
#else
#define OPENVPN_LOG_TUN_VERBOSE(x)
#endif

#endif // OPENVPN_TUN_TUNLOG_H
