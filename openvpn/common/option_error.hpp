//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2022 OpenVPN Inc.
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

#pragma once

#include <cassert>
#include <openvpn/common/exception.hpp>

namespace openvpn {

OPENVPN_EXCEPTION_WITH_CODE(option_error, ERR_PROFILE_OPTION, ERR_INVALID_OPTION_DNS, ERR_INVALID_OPTION_CRYPTO, ERR_INVALID_CONFIG, ERR_INVALID_OPTION_PUSHED, ERR_INVALID_OPTION_VAL);

inline std::string option_error::code2string(option_error_code code)
{
    static const char *code_strings[] = {
        "ERR_INVALID_OPTION_DNS",
        "ERR_INVALID_OPTION_CRYPTO",
        "ERR_INVALID_CONFIG",
        "ERR_INVALID_OPTION_PUSHED",
        "ERR_INVALID_OPTION_VAL"};

    assert(code < sizeof(code_strings));
    return code_strings[code];
}

} // namespace openvpn
