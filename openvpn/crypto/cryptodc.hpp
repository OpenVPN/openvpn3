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

// Base class for OpenVPN data channel encryption/decryption

#ifndef OPENVPN_CRYPTO_CRYPTODC_H
#define OPENVPN_CRYPTO_CRYPTODC_H

#include <openvpn/buffer/buffer.hpp>
#include <openvpn/error/error.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/random/prng.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/crypto/packet_id.hpp>

namespace openvpn {

  // Base class for encryption/decryption of data channel
  template <typename CRYPTO_API>
  class CryptoDCBase : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<CryptoDCBase> Ptr;

    // Initialization

    virtual void init_encrypt_cipher(const StaticKey& key, const int mode) = 0;

    virtual void init_encrypt_hmac(const StaticKey& key) = 0;

    virtual void init_encrypt_pid_send(const int form) = 0;

    virtual void init_decrypt_cipher(const StaticKey& key, const int mode) = 0;

    virtual void init_decrypt_hmac(const StaticKey& key) = 0;

    virtual void init_decrypt_pid_recv(const int mode, const int form,
				       const int seq_backtrack, const int time_backtrack,
				       const char *name, const int unit,
				       const SessionStats::Ptr& stats_arg) = 0;

    // Encrypt/Decrypt

    // returns true if packet ID is close to wrapping
    virtual bool encrypt(BufferAllocated& buf, const PacketID::time_t now) = 0;

    virtual Error::Type decrypt(BufferAllocated& buf, const PacketID::time_t now) = 0;

    // Rekeying

    enum RekeyType {
      ACTIVATE_PRIMARY,
      DEACTIVATE_SECONDARY,
      PROMOTE_SECONDARY_TO_PRIMARY,
      DEACTIVATE_ALL,
    };

    virtual void rekey(const RekeyType type) = 0;
  };

  // Factory for CryptoDCBase objects
  template <typename CRYPTO_API>
  class CryptoDCContext : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<CryptoDCContext> Ptr;

    virtual typename CryptoDCBase<CRYPTO_API>::Ptr new_obj(const unsigned int key_id) = 0;
  };

  // Factory for CryptoDCContext objects
  template <typename CRYPTO_API>
  class CryptoDCFactory : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<CryptoDCFactory> Ptr;

    virtual typename CryptoDCContext<CRYPTO_API>::Ptr new_obj(const typename CRYPTO_API::Cipher& cipher,
							      const typename CRYPTO_API::Digest& digest) = 0;
  };
}

#endif
