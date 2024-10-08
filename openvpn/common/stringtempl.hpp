//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//


// Sometimes you want to accept a <typename STRING> in a
// method, without knowing whether it's a const char *,
// const std::string&, or nullptr.  These methods help with
// basic type-independent string operations.

#ifndef OPENVPN_COMMON_STRINGTEMPL_H
#define OPENVPN_COMMON_STRINGTEMPL_H

#include <string>
#include <cstddef> // for std::nullptr_t
#include <utility>

namespace openvpn::StringTempl {

// empty

inline bool empty(std::nullptr_t)
{
    return true;
}

inline bool empty(const char *str)
{
    return !str || str[0] == '\0';
}

inline bool empty(const std::string &str)
{
    return str.empty();
}

// to_string

inline std::string to_string(std::nullptr_t)
{
    return std::string();
}

inline std::string to_string(const char *str)
{
    if (str)
        return std::string(str);
    else
        return to_string(nullptr);
}

inline std::string to_string(std::string &&str)
{
    return std::move(str);
}

inline const std::string &to_string(const std::string &str)
{
    return str;
}

// to_cstring

inline const char *to_cstring(const std::string &str)
{
    return str.c_str();
}

inline const char *to_cstring(const char *str)
{
    return str;
}
} // namespace openvpn::StringTempl

#endif
