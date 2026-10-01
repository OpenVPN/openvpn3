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
#include <utility>
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

// One directive each, correct only in the order remote_cert() calls them.
namespace detail {

/**
 * @brief Sets both values from remote-cert-tls, or clears them if it is absent.
 *
 * @throws option_error if the argument is not "client" or "server"
 */
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
    KUParse::remote_cert_tls(wt, ku, eku);
}

/**
 * @brief Replaces the key usage values if remote-cert-ku is present. A bare
 *        directive only requires the extension, as in OpenVPN 2.x.
 *
 * @throws option_error if a value is not hex, is 0 (which would match any
 *         certificate), or has a bit outside KU_VALUE_BITS
 */
inline void remote_cert_ku(const OptionList &opt,
                           const std::string &relay_prefix,
                           std::vector<unsigned int> &ku)
{
    const Option *o = opt.get_ptr(relay_prefix + "remote-cert-ku");
    if (!o)
        return;
    if (o->size() >= 64)
        throw option_error(ERR_INVALID_OPTION_CRYPTO, "remote-cert-ku: too many parameters");

    std::vector<unsigned int> values;
    for (size_t i = 1; i < o->size(); ++i)
    {
        // at most 16 hex digits always fit, so a large value cannot wrap into range
        std::uint64_t v;
        if (!parse_hex_number(o->get(i, 16), v))
            throw option_error(ERR_INVALID_OPTION_CRYPTO, "remote-cert-ku: error parsing hex value list");
        if (v == 0 || (v & ~std::uint64_t{KU_VALUE_BITS}) != 0)
            throw option_error(ERR_INVALID_OPTION_CRYPTO, "remote-cert-ku: values must be nonzero and use only the bits 80 to 02");
        values.push_back(static_cast<unsigned int>(v));
    }

    if (values.empty())
        values.push_back(KU_REQUIRED);
    ku = std::move(values);
}

/**
 * @brief Replaces the extended key usage if remote-cert-eku is present.
 *
 * @throws option_error if the value is missing or empty, as an empty one
 *         would turn the check off
 */
inline void remote_cert_eku(const OptionList &opt,
                            const std::string &relay_prefix,
                            std::string &eku)
{
    const Option *o = opt.get_ptr(relay_prefix + "remote-cert-eku");
    if (!o)
        return;

    std::string value = o->get(1, 256);
    if (value.empty())
        throw option_error(ERR_INVALID_OPTION_CRYPTO, "remote-cert-eku: empty value");
    eku = std::move(value);
}

} // namespace detail

/**
 * @brief Parses remote-cert-tls, remote-cert-ku and remote-cert-eku.
 *
 * remote-cert-tls sets both values; an explicit remote-cert-ku or
 * remote-cert-eku replaces its half wherever it appears in the profile.
 *
 * @param opt           the parsed profile
 * @param relay_prefix  "relay-" to read the relay variants, else empty
 * @param ku            receives the key usage values, empty for no check
 * @param eku           receives the extended key usage, empty for no check
 * @throws option_error on an invalid directive, leaving @p ku and @p eku
 *         unspecified
 */
inline void remote_cert(const OptionList &opt,
                        const std::string &relay_prefix,
                        std::vector<unsigned int> &ku,
                        std::string &eku)
{
    detail::remote_cert_tls(opt, relay_prefix, ku, eku);
    detail::remote_cert_ku(opt, relay_prefix, ku);
    detail::remote_cert_eku(opt, relay_prefix, eku);
}
} // namespace openvpn::KUParse

#endif
