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

#ifndef OPENVPN_PKI_PKCS1_H
#define OPENVPN_PKI_PKCS1_H

#include <cstring>

#include <openvpn/common/size.hpp>
#include <openvpn/buffer/buffer.hpp>

// from http://www.ietf.org/rfc/rfc3447.txt
namespace openvpn::PKCS1::DigestPrefix { // CONST GLOBAL
namespace {
// clang-format off
const unsigned char MD2[] = {
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x02, 0x02, 0x05, 0x00, 0x04, 0x10
};
const unsigned char MD5[] = {
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
const unsigned char SHA1[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
    0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
    0x00, 0x04, 0x14
};
const unsigned char SHA256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
    0x20 };
const unsigned char SHA384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
    0x30
};
const unsigned char SHA512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x03, 0x05, 0x00, 0x04,
    0x40
};
// clang-format on
} // namespace

/**
 * Class that parses an PKCS #1 header (RFC 3447) to identify the used digest type
 * @tparam T    the type of the crypto library that used should be used for the digest algorithm identification
 */
template <typename T>
class Parse
{
  public:
    Parse(const T none,
          const T md2,
          const T md5,
          const T sha1,
          const T sha256,
          const T sha384,
          const T sha512)
        : none_(none),
          md2_(md2),
          md5_(md5),
          sha1_(sha1),
          sha256_(sha256),
          sha384_(sha384),
          sha512_(sha512)
    {
    }

    /** Constructor for TLS libraries that no longer support MD2  */
    Parse(const T none,
          const T md5,
          const T sha1,
          const T sha256,
          const T sha384,
          const T sha512)
        : none_(none),
          md2_(none),
          md5_(md5),
          sha1_(sha1),
          sha256_(sha256),
          sha384_(sha384),
          sha512_(sha512)
    {
    }

    T alg_from_prefix(Buffer &buf) const
    {
        if (match(buf, MD2, sizeof(MD2)))
            return md2_;
        else if (match(buf, MD5, sizeof(MD5)))
            return md5_;
        else if (match(buf, SHA1, sizeof(SHA1)))
            return sha1_;
        else if (match(buf, SHA256, sizeof(SHA256)))
            return sha256_;
        else if (match(buf, SHA384, sizeof(SHA384)))
            return sha384_;
        else if (match(buf, SHA512, sizeof(SHA512)))
            return sha512_;
        else
            return none_;
    }

  private:
    bool match(Buffer &buf, const unsigned char *data, const size_t size) const
    {
        if (buf.size() < size)
            return false;
        else if (std::memcmp(buf.c_data(), data, size) == 0)
        {
            buf.advance(size);
            return true;
        }
        else
            return false;
    }

    const T none_, md2_, md5_, sha1_, sha256_, sha384_, sha512_;
};
} // namespace openvpn::PKCS1::DigestPrefix

#endif
