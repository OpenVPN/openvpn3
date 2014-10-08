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

// OpenVPN CBC/HMAC data channel

#ifndef OPENVPN_CRYPTO_CRYPTO_CHM_H
#define OPENVPN_CRYPTO_CRYPTO_CHM_H

#include <openvpn/crypto/encrypt.hpp>
#include <openvpn/crypto/decrypt.hpp>
#include <openvpn/crypto/cryptobase.hpp>

namespace openvpn {

  template <typename RAND_API, typename CRYPTO_API>
  class CryptoContextCHM : public CryptoContextBase<RAND_API, CRYPTO_API>
  {
    typedef CryptoContextBase<RAND_API, CRYPTO_API> Base;

    virtual void init_frame(const Frame::Ptr& frame)
    {
      encrypt_.frame = frame;
      decrypt_.frame = frame;
    }

    virtual void init_prng(const typename PRNG<RAND_API, CRYPTO_API>::Ptr& prng)
    {
      encrypt_.prng = prng;
    }

    virtual void init_encrypt_cipher(const typename CRYPTO_API::Cipher& cipher,
				     const StaticKey& key, const int mode)
    {
      encrypt_.cipher.init(cipher, key, mode);
    }

    virtual void init_encrypt_hmac(const typename CRYPTO_API::Digest& digest,
				   const StaticKey& key)
    {
      encrypt_.hmac.init(digest, key);
    }

    virtual void init_encrypt_pid_send(const int form)
    {
      encrypt_.pid_send.init(form);
    }

    virtual void init_decrypt_cipher(const typename CRYPTO_API::Cipher& cipher,
				     const StaticKey& key, const int mode)
    {
      decrypt_.cipher.init(cipher, key, mode);
    }

    virtual void init_decrypt_hmac(const typename CRYPTO_API::Digest& digest,
				   const StaticKey& key)
    {
      decrypt_.hmac.init(digest, key);
    }

    virtual void init_decrypt_pid_recv(const int mode, const int form,
				       const int seq_backtrack, const int time_backtrack,
				       const char *name, const int unit,
				       const SessionStats::Ptr& stats_arg)
    {
      decrypt_.pid_recv.init(mode, form, seq_backtrack, time_backtrack, name, unit, stats_arg);
    }

    /* returns true if packet ID is close to wrapping */
    virtual bool encrypt(BufferAllocated& buf, const PacketID::time_t now)
    {
      encrypt_.encrypt(buf, now);
      return encrypt_.pid_send.wrap_warning();
    }

    virtual Error::Type decrypt(BufferAllocated& buf, const PacketID::time_t now)
    {
      return decrypt_.decrypt(buf, now);
    }

    virtual void rekey(const typename Base::RekeyType type)
    {
    }

  private:
    Encrypt<RAND_API, CRYPTO_API> encrypt_;
    Decrypt<CRYPTO_API> decrypt_;
  };

  template <typename RAND_API, typename CRYPTO_API>
  class CryptoContextCHMFactory : public CryptoContextFactory<RAND_API, CRYPTO_API>
  {
    virtual typename CryptoContextBase<RAND_API, CRYPTO_API>::Ptr new_obj(const unsigned int key_id)
    {
      return new CryptoContextCHM<RAND_API, CRYPTO_API>();
    }
  };

}

#endif
