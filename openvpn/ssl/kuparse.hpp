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

// Parse the remote-cert-tls, remote-cert-ku, and remote-cert-eku options.

#ifndef OPENVPN_SSL_KUPARSE_H
#define OPENVPN_SSL_KUPARSE_H

#include <cstdint>
#include <vector>
#include <string>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/hexstr.hpp>
#include <openvpn/common/options.hpp>

namespace openvpn::KUParse {
enum TLSWebType
{
    TLS_WEB_NONE,
    TLS_WEB_SERVER,
    TLS_WEB_CLIENT,
};

/**
 * @brief Key usage list entry that only requires the peer certificate to have a
 *        key usage extension, as OPENVPN_KU_REQUIRED does in OpenVPN 2.x.
 *
 * The bits are left to the TLS library. mbed TLS checks them against the key
 * exchange. OpenSSL only requires a bit that some TLS key exchange could use,
 * so it accepts a TLS 1.3 peer whose key usage lacks the digitalSignature its
 * handshake needs; OpenVPN 2.x has the same gap.
 */
inline constexpr unsigned int KU_REQUIRED = 0xFFFF;

/**
 * @brief Key usage bits a remote-cert-ku value may use: digitalSignature (80)
 *        to cRLSign (02).
 *
 * encipherOnly (01) and decipherOnly (8000) are left out: mbed TLS treats them
 * as optional, so a value of only those would match any certificate, and the
 * OpenSSL backend reads only the first byte.
 */
inline constexpr unsigned int KU_VALUE_BITS = 0xfe;

inline void remote_cert_tls(const TLSWebType wt, std::vector<unsigned int> &ku, std::string &eku)
{
    ku.clear();
    eku = "";

    switch (wt)
    {
    case TLS_WEB_NONE:
        break;
    case TLS_WEB_SERVER:
        ku.push_back(KU_REQUIRED);
        eku = "TLS Web Server Authentication";
        break;
    case TLS_WEB_CLIENT:
        ku.push_back(KU_REQUIRED);
        eku = "TLS Web Client Authentication";
        break;
    }
}

inline TLSWebType remote_cert_type(const std::string &ct)
{
    if (ct == "server")
        return TLS_WEB_SERVER;
    else if (ct == "client")
        return TLS_WEB_CLIENT;
    else
        throw option_error(ERR_INVALID_OPTION_CRYPTO, "remote-cert-tls must be 'client' or 'server'");
}

inline void remote_cert_tls(const std::string &ct,
                            std::vector<unsigned int> &ku,
                            std::string &eku)
{
    remote_cert_tls(remote_cert_type(ct), ku, eku);
}

inline void remote_cert_tls(const OptionList &opt,
                            const std::string &relay_prefix,
                            std::vector<unsigned int> &ku,
                            std::string &eku)
{
    TLSWebType wt = TLS_WEB_NONE;
    const Option *o = opt.get_ptr(relay_prefix + "remote-cert-tls");
    if (o)
    {
        const std::string ct = o->get_optional(1, 16);
        wt = remote_cert_type(ct);
    }
    remote_cert_tls(wt, ku, eku);
}

inline void remote_cert_ku(const OptionList &opt,
                           const std::string &relay_prefix,
                           std::vector<unsigned int> &ku)
{
    ku.clear();

    const Option *o = opt.get_ptr(relay_prefix + "remote-cert-ku");
    if (o)
    {
        if (o->empty())
            throw option_error(ERR_INVALID_OPTION_CRYPTO, "remote-cert-ku: no hex values specified");
        else if (o->size() >= 64)
            throw option_error(ERR_INVALID_OPTION_CRYPTO, "remote-cert-ku: too many parameters");
        else
        {
            for (size_t i = 1; i < o->size(); ++i)
            {
                // at most 16 hex digits always fit, so a large value cannot wrap into range
                std::uint64_t v;
                if (!parse_hex_number(o->get(i, 16), v))
                    throw option_error(ERR_INVALID_OPTION_CRYPTO, "remote-cert-ku: error parsing hex value list");
                if (v == 0 || (v & ~std::uint64_t{KU_VALUE_BITS}) != 0)
                    throw option_error(ERR_INVALID_OPTION_CRYPTO, "remote-cert-ku: values must be nonzero and use only the bits 80 to 02");
                ku.push_back(static_cast<unsigned int>(v));
            }
        }
    }
}

inline void remote_cert_eku(const OptionList &opt,
                            const std::string &relay_prefix,
                            std::string &eku)
{
    eku = "";

    const Option *o = opt.get_ptr(relay_prefix + "remote-cert-eku");
    if (o)
        eku = o->get(1, 256);
}
} // namespace openvpn::KUParse

#endif
