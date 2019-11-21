//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Inc.
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

#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <openvpn/pki/epkibase.hpp>
#include <openvpn/ssl/sslapi.hpp>

#include <openvpn/openssl/compat.hpp>

namespace openvpn {
  using ssl_external_pki = SSLFactoryAPI::ssl_external_pki;

  class ExternalPKIImpl
  {
  public:
    virtual ~ExternalPKIImpl() = default;
  };

  class ExternalPKIRsaImpl : public ExternalPKIImpl
  {
  public:
    ExternalPKIRsaImpl(SSL_CTX* ssl_ctx, ::X509* cert, ExternalPKIBase* external_pki_arg)
      : external_pki(external_pki_arg), n_errors(0)
    {
      RSA* rsa = nullptr;
      RSA* pub_rsa = nullptr;
      RSA_METHOD* rsa_meth = nullptr;
      const char* errtext = "";

      /* allocate custom RSA method object */
      rsa_meth = RSA_meth_new("OpenSSLContext::ExternalPKIRsaImpl private key RSA Method", RSA_METHOD_FLAG_NO_CHECK);

      RSA_meth_set_pub_enc(rsa_meth, rsa_pub_enc);
      RSA_meth_set_pub_dec(rsa_meth, rsa_pub_dec);
      RSA_meth_set_priv_enc(rsa_meth, rsa_priv_enc);
      RSA_meth_set_priv_dec(rsa_meth, rsa_priv_dec);
      RSA_meth_set_init(rsa_meth, nullptr);
      RSA_meth_set_finish(rsa_meth, rsa_finish);
      RSA_meth_set0_app_data(rsa_meth, this);

      /* allocate RSA object */
      rsa = RSA_new();
      if (rsa == nullptr)
	{
	  SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
	  errtext = "RSA_new";
	  goto err;
	}

      /* get the public key */
      if (X509_get0_pubkey(cert) == nullptr) /* nullptr before SSL_CTX_use_certificate() is called */
	{
	  errtext = "pkey is NULL";
	  goto err;
	}

      if (EVP_PKEY_id(X509_get0_pubkey(cert)) != EVP_PKEY_RSA)
	{
	  errtext = "pkey is not RSA";
	  goto err;
	}
      pub_rsa = EVP_PKEY_get0_RSA(X509_get0_pubkey(cert));

      /* initialize RSA object */
      rsa = RSA_new();

      /* only set e and n as d (private key) is outside our control */
      RSA_set0_key(rsa, BN_dup(RSA_get0_n(pub_rsa)), BN_dup(RSA_get0_e(pub_rsa)), nullptr);
      RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);

      if (!RSA_set_method(rsa, rsa_meth))
	{
	  errtext = "RSA_set_method";
	  goto err;
	}

      /* bind our custom RSA object to ssl_ctx */
      if (!SSL_CTX_use_RSAPrivateKey(ssl_ctx, rsa))
	{
	  errtext = "SSL_CTX_use_RSAPrivateKey";
	  goto err;
	}

      RSA_free(rsa); /* doesn't necessarily free, just decrements refcount */
      return;

      err:
      if (rsa)
	RSA_free(rsa);
      else
	{
	  if (rsa_meth)
	    RSA_meth_free(rsa_meth);
	}
      OPENVPN_THROW(OpenSSLException, "OpenSSLContext::ExternalPKIRsaImpl: " << errtext);
    }

    ~ExternalPKIRsaImpl() override = default;

    unsigned int get_n_errors() const
    { return n_errors; }

  private:
    /* called at RSA_free */
    static int rsa_finish(RSA* rsa)
    {
      RSA_meth_free(const_cast<RSA_METHOD*>(RSA_get_method(rsa)));
      return 1;
    }

    /* sign arbitrary data */
    static int
    rsa_priv_enc(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
    {
      ExternalPKIRsaImpl* self = (ExternalPKIRsaImpl*) (RSA_meth_get0_app_data(RSA_get_method(rsa)));

      try
	{
	  if (padding != RSA_PKCS1_PADDING && padding != RSA_NO_PADDING)
	    {
	      RSAerr (RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
	      throw ssl_external_pki("OpenSSL: bad padding type");
	    }
	  std::string padding_algo;
	  if (padding == RSA_PKCS1_PADDING)
	    {
	      padding_algo = "RSA_PKCS1_PADDING";
	    }
	  else if (padding == RSA_NO_PADDING)
	    {
	      padding_algo = "RSA_NO_PADDING";
	    }

	  /* convert 'from' to base64 */
	  ConstBuffer from_buf(from, flen, true);
	  const std::string from_b64 = base64->encode(from_buf);

	  /* get signature */
	  std::string sig_b64;
	  const bool status = self->external_pki->sign(from_b64, sig_b64, padding_algo);
	  if (!status)
	    throw ssl_external_pki("OpenSSL: could not obtain signature");

	  /* decode base64 signature to binary */
	  const int len = RSA_size(rsa);
	  Buffer sig(to, len, false);
	  base64->decode(sig, sig_b64);

	  /* verify length */
	  if (sig.size() != len)
	    throw ssl_external_pki("OpenSSL: incorrect signature length");

	  /* return length of signature */
	  return len;
	}
      catch (const std::exception& e)
	{
	  OPENVPN_LOG("OpenSSLContext::ExternalPKIRsaImpl::rsa_priv_enc exception: " << e.what());
	  ++self->n_errors;
	  return -1;
	}
    }

    static void not_implemented(RSA* rsa)
    {
      ExternalPKIRsaImpl* self = (ExternalPKIRsaImpl*) (RSA_meth_get0_app_data(RSA_get_method(rsa)));
      ++self->n_errors;
    }

    /* encrypt */
    static int
    rsa_pub_enc(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
    {
      not_implemented(rsa);
      return -1;
    }

    /* verify arbitrary data */
    static int
    rsa_pub_dec(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
    {
      not_implemented(rsa);
      return -1;
    }

    /* decrypt */
    static int
    rsa_priv_dec(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
    {
      not_implemented(rsa);
      return -1;
    }

    ExternalPKIBase* external_pki;
    unsigned int n_errors;
  };

}