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

#pragma once

#include <sstream>
#include <string>
#include <string_view>

#include <openvpn/common/string.hpp>

namespace openvpn::HTTP {

namespace detail {

// Redact the credential of an Authorization (or Proxy-Authorization)
// header contained in line. Matching is case-insensitive and accepts
// both the wire format ("Authorization: Basic xxx") and the
// name=value format produced by HeaderList::to_string()
// ("[3] Authorization=Basic xxx").
// Everything after the scheme is redacted, up to the end of the line
// (a trailing '\r' is preserved).
inline void header_line_redact(std::string &line)
{
    static constexpr std::string_view key = "authorization";
    static constexpr const char *whitespace = " \t";
    static constexpr const char *tok_end = " \t\r";

    const std::string lower = string::to_lower_copy(line);
    for (size_t auth_pos = lower.find(key); auth_pos != std::string::npos; auth_pos = lower.find(key, auth_pos + 1))
    {
        // expect optional whitespace, then ':' or '='
        size_t pos = line.find_first_not_of(whitespace, auth_pos + key.size());
        if (pos == std::string::npos || (line.at(pos) != ':' && line.at(pos) != '='))
            continue;
        pos = line.find_first_not_of(whitespace, pos + 1);
        if (pos == std::string::npos || line.at(pos) == '\r')
            return; // empty value, nothing to redact

        // value is either "<scheme> <credential>" or just "<credential>"
        size_t cred_pos = pos;
        const size_t tok1_end = line.find_first_of(tok_end, pos);
        if (tok1_end != std::string::npos)
        {
            const size_t tok2_pos = line.find_first_not_of(whitespace, tok1_end);
            if (tok2_pos != std::string::npos && line.at(tok2_pos) != '\r')
                cred_pos = tok2_pos; // keep the scheme, redact what follows
        }
        size_t cred_end = line.size();
        if (line.back() == '\r')
            --cred_end;
        line.replace(cred_pos, cred_end - cred_pos, "[REDACTED]");
        return;
    }
}

} // namespace detail

inline std::string headers_redact(const std::string &headers)
{
#ifdef OPENVPN_HTTP_HEADERS_NO_REDACT
    return headers;
#else
    std::ostringstream result;
    std::istringstream iss(headers);

    for (std::string line; std::getline(iss, line);)
    {
        detail::header_line_redact(line);
        result << line << '\n';
    }
    return result.str();
#endif
}

} // namespace openvpn::HTTP
