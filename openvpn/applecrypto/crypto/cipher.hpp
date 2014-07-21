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

// Wrap the Apple cipher API defined in <CommonCrypto/CommonCryptor.h> so
// that it can be used as part of the crypto layer of the OpenVPN core.

#ifndef OPENVPN_APPLECRYPTO_CRYPTO_CIPHER_H
#define OPENVPN_APPLECRYPTO_CRYPTO_CIPHER_H

#include <string>
#include <cstring>

#include <CommonCrypto/CommonCryptor.h>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/platform.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/crypto/static_key.hpp>
#include <openvpn/applecrypto/cf/error.hpp>

namespace openvpn {
  namespace AppleCrypto {

    class CipherInfo
    {
    public:
      CipherInfo(const char *name,
		 const size_t key_size,
		 const size_t iv_length,
		 const size_t block_size,
		 const CCAlgorithm algorithm)
	: name_(name),
	  key_size_(key_size),
	  iv_length_(iv_length),
	  block_size_(block_size),
	  algorithm_(algorithm) {}

      bool name_match(const char *name) const
      {
	return string::strcasecmp(name, name_) == 0;
      }

      const char *name() const { return name_; }
      size_t key_length() const { return key_size_; }
      size_t iv_length() const { return iv_length_; }
      size_t block_size() const { return block_size_; }

      CCAlgorithm algorithm() const { return algorithm_; }

    private:
      const char *name_;
      size_t key_size_;
      size_t iv_length_;
      size_t block_size_;
      CCAlgorithm algorithm_;
    };

    const CipherInfo aes128("AES-128-CBC", kCCKeySizeAES128, kCCBlockSizeAES128, // CONST GLOBAL
			    kCCBlockSizeAES128, kCCAlgorithmAES128);
    const CipherInfo aes192("AES-192-CBC", kCCKeySizeAES192, kCCBlockSizeAES128, // CONST GLOBAL
			    kCCBlockSizeAES128, kCCAlgorithmAES128);
    const CipherInfo aes256("AES-256-CBC", kCCKeySizeAES256, kCCBlockSizeAES128, // CONST GLOBAL
			    kCCBlockSizeAES128, kCCAlgorithmAES128);
    const CipherInfo des3("DES-EDE3-CBC", kCCKeySize3DES, kCCBlockSize3DES, // CONST GLOBAL
			  kCCBlockSize3DES, kCCAlgorithm3DES);
    const CipherInfo des("DES-CBC", kCCKeySizeDES, kCCBlockSizeDES, // CONST GLOBAL
			 kCCBlockSizeDES, kCCAlgorithmDES);

#ifdef OPENVPN_PLATFORM_IPHONE
    const CipherInfo bf("BF-CBC", 16, kCCBlockSizeBlowfish, // CONST GLOBAL
			kCCBlockSizeBlowfish, kCCAlgorithmBlowfish);
#endif

    class CipherContext;

    class Cipher
    {
      friend class CipherContext;

    public:
      OPENVPN_EXCEPTION(cipher_not_found);
      OPENVPN_SIMPLE_EXCEPTION(cipher_undefined);

      Cipher() : cipher_(NULL) {}


      Cipher(const std::string& name)
      {
#       define OPENVPN_CIPHER_SELECT(TYPE) if (TYPE.name_match(name.c_str())) { cipher_ = &TYPE; return; }
#       ifdef OPENVPN_PLATFORM_IPHONE
          OPENVPN_CIPHER_SELECT(bf);
#       endif
	OPENVPN_CIPHER_SELECT(aes128);
	OPENVPN_CIPHER_SELECT(aes192);
	OPENVPN_CIPHER_SELECT(aes256);
	OPENVPN_CIPHER_SELECT(des3);
	OPENVPN_CIPHER_SELECT(des);
	throw cipher_not_found(name);
#       undef OPENVPN_CIPHER_SELECT
      }

      std::string name() const
      {
	check_initialized();
	return cipher_->name();
      }

      size_t key_length() const
      {
	check_initialized();
	return cipher_->key_length();
      }

      size_t key_length_in_bits() const
      {
	check_initialized();
	return cipher_->key_length() * 8;
      }

      size_t iv_length() const
      {
	check_initialized();
	return cipher_->iv_length();
      }

      size_t block_size() const
      {
	check_initialized();
	return cipher_->block_size();
      }

      bool defined() const { return cipher_ != NULL; }

    private:
      const CipherInfo *get() const
      {
	check_initialized();
	return cipher_;
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!cipher_)
	  throw cipher_undefined();
#endif
      }

      const CipherInfo *cipher_;
    };

    class CipherContext : boost::noncopyable
    {
    public:
      OPENVPN_SIMPLE_EXCEPTION(cipher_mode_error);
      OPENVPN_SIMPLE_EXCEPTION(cipher_uninitialized);

      // mode parameter for constructor
      enum {
	MODE_UNDEF = -1,
	ENCRYPT = kCCEncrypt,
	DECRYPT = kCCDecrypt
      };

      enum {
	MAX_IV_LENGTH = 16,
	CIPH_CBC_MODE = 0
      };

      CipherContext()
	: cinfo(NULL), cref(NULL)
      {
      }

      ~CipherContext() { erase() ; }

      void init()
      {
      }

      void init(const Cipher& cipher, const unsigned char *key, const int mode)
      {
	erase();

	// check that mode is valid
	if (!(mode == ENCRYPT || mode == DECRYPT))
	  throw cipher_mode_error();

	// get cipher type
	const CipherInfo *ci = cipher.get();

	// initialize cipher context with cipher type
	const CCCryptorStatus status = CCCryptorCreate(mode,
						       ci->algorithm(),
						       kCCOptionPKCS7Padding,
						       key,
						       ci->key_length(),
						       NULL,
						       &cref);
	if (status != kCCSuccess)
	  throw CFException("CipherContext: CCCryptorCreate", status);

	cinfo = ci;
      }

      void reset(const unsigned char *iv)
      {
	check_initialized();
	const CCCryptorStatus status = CCCryptorReset(cref, iv);
	if (status != kCCSuccess)
	  throw CFException("CipherContext: CCCryptorReset", status);
      }

      bool update(unsigned char *out, const size_t max_out_size,
		  const unsigned char *in, const size_t in_size,
		  size_t& out_acc)
      {
	check_initialized();
	size_t dataOutMoved;
	const CCCryptorStatus status = CCCryptorUpdate(cref, in, in_size, out, max_out_size, &dataOutMoved);
	if (status == kCCSuccess)
	  {
	    out_acc += dataOutMoved;
	    return true;
	  }
	else
	  return false;
      }

      bool final(unsigned char *out, const size_t max_out_size, size_t& out_acc)
      {
	check_initialized();
	size_t dataOutMoved;
	const CCCryptorStatus status = CCCryptorFinal(cref, out, max_out_size, &dataOutMoved);
	if (status == kCCSuccess)
	  {
	    out_acc += dataOutMoved;
	    return true;
	  }
	else
	  return false;
      }

      bool is_initialized() const { return cinfo != NULL; }

      size_t iv_length() const
      {
	check_initialized();
	return cinfo->iv_length();
      }

      size_t block_size() const
      {
	check_initialized();
	return cinfo->block_size();
      }

      // return cipher mode (such as CIPH_CBC_MODE, etc.)
      int cipher_mode() const
      {
	check_initialized();
	return CIPH_CBC_MODE;
      }

    private:
      void erase()
      {
	if (cinfo)
	  {
	    if (cref)
	      CCCryptorRelease(cref);
	    cref = NULL;
	    cinfo = NULL;
	  }
      }

      void check_initialized() const
      {
#ifdef OPENVPN_ENABLE_ASSERT
	if (!cinfo)
	  throw cipher_uninitialized();
#endif
      }

      const CipherInfo *cinfo;
      CCCryptorRef cref;
    };
  }
}

#endif
