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

// Crypto digest API

#ifndef OPENVPN_CRYPTO_DIGESTAPI_H
#define OPENVPN_CRYPTO_DIGESTAPI_H

#include <openvpn/common/rc.hpp>
#include <openvpn/crypto/cryptoalgs.hpp>

namespace openvpn {

  // Digest abstract base classes and factories

  class DigestInstance : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<DigestInstance> Ptr;

    virtual void update(const unsigned char *in, const size_t size) = 0;
    virtual size_t final(unsigned char *out) = 0;
  };

  class DigestContext : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<DigestContext> Ptr;

    virtual std::string name() const = 0;
    virtual size_t size() const = 0;

    virtual DigestInstance::Ptr new_obj() = 0;
  };

  class DigestFactory : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<DigestFactory> Ptr;

    virtual DigestContext::Ptr new_obj(const CryptoAlgs::Type digest_type) = 0;
  };

  // Digest implementation using CRYPTO_API

  template <typename CRYPTO_API>
  class CryptoDigestInstance : public DigestInstance
  {
  public:
    CryptoDigestInstance(const typename CRYPTO_API::Digest& digest)
      : impl(digest)
    {
    }

    virtual void update(const unsigned char *in, const size_t size)
    {
      impl.update(in, size);
    }

    virtual size_t final(unsigned char *out)
    {
      return impl.final(out);
    }

  private:
    typename CRYPTO_API::DigestContext impl;
  };

  template <typename CRYPTO_API>
  class CryptoDigestContext : public DigestContext
  {
  public:
    CryptoDigestContext(const CryptoAlgs::Type digest_type)
      : digest(digest_type)
    {
    }

    virtual std::string name() const
    {
      return digest.name();
    }

    virtual size_t size() const
    {
      return digest.size();
    }

    virtual DigestInstance::Ptr new_obj()
    {
      return new CryptoDigestInstance<CRYPTO_API>(digest);
    }

  private:
    typename CRYPTO_API::Digest digest;
  };

  template <typename CRYPTO_API>
  class CryptoDigestFactory : public DigestFactory
  {
  public:
    virtual DigestContext::Ptr new_obj(const CryptoAlgs::Type digest_type)
    {
      return new CryptoDigestContext<CRYPTO_API>(digest_type);
    }
  };

}

#endif
