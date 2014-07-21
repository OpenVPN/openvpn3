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

// Wrap the OpenSSL SSL API as defined in <openssl/ssl.h>
// so that it can be used as the SSL layer by the OpenVPN core.

#ifndef OPENVPN_OPENSSL_SSL_SSLCTX_H
#define OPENVPN_OPENSSL_SSL_SSLCTX_H

#include <string>
#include <cstring>
#include <sstream>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/mode.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/pki/cclist.hpp>
#include <openvpn/pki/epkibase.hpp>
#include <openvpn/ssl/kuparse.hpp>
#include <openvpn/ssl/nscert.hpp>
#include <openvpn/ssl/tlsver.hpp>
#include <openvpn/ssl/tls_remote.hpp>
#include <openvpn/openssl/util/error.hpp>
#include <openvpn/openssl/pki/x509.hpp>
#include <openvpn/openssl/pki/crl.hpp>
#include <openvpn/openssl/pki/pkey.hpp>
#include <openvpn/openssl/pki/dh.hpp>
#include <openvpn/openssl/pki/x509store.hpp>
#include <openvpn/openssl/bio/bio_memq_stream.hpp>
#include <openvpn/openssl/util/free.hpp>

// An SSL Context is essentially a configuration that can be used
// to generate an arbitrary number of actual SSL connections objects.

// OpenSSLContext is an SSL Context implementation that uses the
// OpenSSL library as a backend.

namespace openvpn {

  // Represents an SSL configuration that can be used
  // to instantiate actual SSL sessions.
  class OpenSSLContext : public RC<thread_unsafe_refcount>
  {
  public:
    OPENVPN_EXCEPTION(ssl_context_error);
    OPENVPN_EXCEPTION(ssl_ciphertext_in_overflow);

    typedef boost::intrusive_ptr<OpenSSLContext> Ptr;
    typedef CertCRLListTemplate<OpenSSLPKI::X509List, OpenSSLPKI::CRLList> CertCRLList;

    enum {
      MAX_CIPHERTEXT_IN = 64 // maximum number of queued input ciphertext packets
    };

    // The data needed to construct an OpenSSLContext.
    struct Config
    {
      Config() : external_pki(NULL),
		 ssl_debug_level(0),
		 ns_cert_type(NSCert::NONE),
		 tls_version_min(TLSVersion::UNDEF),
		 local_cert_enabled(true),
		 force_aes_cbc_ciphersuites(false) {}

      Mode mode;
      CertCRLList ca;                   // from OpenVPN "ca" option
      OpenSSLPKI::X509 cert;            // from OpenVPN "cert" option
      OpenSSLPKI::X509List extra_certs; // from OpenVPN "extra-certs" option
      OpenSSLPKI::PKey pkey;            // private key
      OpenSSLPKI::DH dh;                // diffie-hellman parameters (only needed in server mode)
      ExternalPKIBase* external_pki;
      Frame::Ptr frame;
      int ssl_debug_level;
      NSCert::Type ns_cert_type;
      std::vector<unsigned int> ku; // if defined, peer cert X509 key usage must match one of these values
      std::string eku;              // if defined, peer cert X509 extended key usage must match this OID/string
      std::string tls_remote;
      TLSVersion::Type tls_version_min; // minimum TLS version that we will negotiate
      bool local_cert_enabled;
      bool force_aes_cbc_ciphersuites;

      // if this callback is defined, no private key needs to be loaded
      void set_external_pki_callback(ExternalPKIBase* external_pki_arg)
      {
	external_pki = external_pki_arg;
      }

      void set_private_key_password(const std::string& pwd)
      {
	pkey.set_private_key_password(pwd);
      }

      void load_ca(const std::string& ca_txt)
      {
	ca.parse_pem(ca_txt, "ca");
      }

      void load_cert(const std::string& cert_txt)
      {
	cert.parse_pem(cert_txt, "cert");
      }

      void load_extra_certs(const std::string& ec_txt)
      {
	if (!ec_txt.empty())
	  CertCRLList::from_string(ec_txt, "extra-certs", &extra_certs, NULL);
      }

      void load_private_key(const std::string& key_txt)
      {
	pkey.parse_pem(key_txt, "private key");
      }

      void load_dh(const std::string& dh_txt)
      {
	dh.parse_pem(dh_txt);
      }

      void load(const OptionList& opt)
      {
	// client/server
	mode = opt.exists("client") ? Mode(Mode::CLIENT) : Mode(Mode::SERVER);

	// ca
	{
	  const std::string ca_txt = opt.cat("ca");
	  load_ca(ca_txt);
	}

	// local cert/key
	if (local_cert_enabled)
	  {
	    // cert
	    {
	      const std::string& cert_txt = opt.get("cert", 1, Option::MULTILINE);
	      load_cert(cert_txt);
	    }

	    // extra-certs
	    {
	      const std::string ec_txt = opt.cat("extra-certs");
	      load_extra_certs(ec_txt);
	    }

	    // private key
	    if (!external_pki)
	      {
		const std::string& key_txt = opt.get("key", 1, Option::MULTILINE);
		load_private_key(key_txt);
	      }
	  }

	// DH
	if (mode.is_server())
	  {
	    const std::string& dh_txt = opt.get("dh", 1, Option::MULTILINE);
	    load_dh(dh_txt);
	  }

	// ns-cert-type
	ns_cert_type = NSCert::ns_cert_type(opt);

	// parse remote-cert-x options
	KUParse::remote_cert_tls(opt, ku, eku);
	KUParse::remote_cert_ku(opt, ku);
	KUParse::remote_cert_eku(opt, eku);

	// parse tls-remote
	tls_remote = opt.get_optional("tls-remote", 1, 256);

	// Parse tls-version-min option.
	// Assume that presence of SSL_OP_NO_TLSvX macro indicates
	// that local OpenSSL library implements TLSvX.
	{
#         if defined(SSL_OP_NO_TLSv1_2)
	    const TLSVersion::Type maxver = TLSVersion::V1_2;
#         elif defined(SSL_OP_NO_TLSv1_1)
	    const TLSVersion::Type maxver = TLSVersion::V1_1;
#         else
            const TLSVersion::Type maxver = TLSVersion::V1_0;
#         endif
	  tls_version_min = TLSVersion::parse_tls_version_min(opt, maxver);
	}

	// unsupported cert checkers
	{
	}
      }
    };

    // Represents an actual SSL session.
    // Normally instantiated by OpenSSLContext::ssl().
    class SSL : public RC<thread_unsafe_refcount>
    {
      friend class OpenSSLContext;

    public:
      typedef boost::intrusive_ptr<SSL> Ptr;

      enum {
	SHOULD_RETRY = -1
      };

      void start_handshake()
      {
	SSL_do_handshake(ssl);
      }

      ssize_t write_cleartext_unbuffered(const void *data, const size_t size)
      {
	const int status = BIO_write(ssl_bio, data, size);
	if (status != int(size))
	  {
	    if (status == -1 && BIO_should_retry(ssl_bio))
	      return SHOULD_RETRY;
	    else
	      OPENVPN_THROW(OpenSSLException, "OpenSSLContext::SSL::write_cleartext: BIO_write failed, size=" << size << " status=" << status);
	  }
	else
	  return status;
      }

      ssize_t read_cleartext(void *data, const size_t capacity)
      {
	if (!overflow)
	  {
	    const int status = BIO_read(ssl_bio, data, capacity);
	    if (status < 0)
	      {
		if (status == -1 && BIO_should_retry(ssl_bio))
		  return SHOULD_RETRY;
		else
		  OPENVPN_THROW(OpenSSLException, "OpenSSLContext::SSL::read_cleartext: BIO_read failed, cap=" << capacity << " status=" << status);
	      }
	    else
	      return status;
	  }
	else
	  throw ssl_ciphertext_in_overflow();
      }

      bool write_ciphertext_ready() const {
	return !bmq_stream::memq_from_bio(ct_in)->empty();
      }

      void write_ciphertext(const BufferPtr& buf)
      {
	bmq_stream::MemQ* in = bmq_stream::memq_from_bio(ct_in);
	if (in->size() < MAX_CIPHERTEXT_IN)
	  in->write_buf(buf);
	else
	  overflow = true;
      }

      bool read_ciphertext_ready() const {
	return !bmq_stream::memq_from_bio(ct_out)->empty();
      }

      BufferPtr read_ciphertext()
      {
	return bmq_stream::memq_from_bio(ct_out)->read_buf();
      }

      std::string ssl_handshake_details() const
      {
	return ssl_handshake_details(ssl);
      }

      ~SSL()
      {
	ssl_erase();
      }

    private:
      SSL(const OpenSSLContext& ctx)
      {
	ssl_clear();
	try {
	  // init SSL objects
	  ssl = SSL_new(ctx.ctx);
	  if (!ssl)
	    throw OpenSSLException("OpenSSLContext::SSL: SSL_new failed");
	  ssl_bio = BIO_new(BIO_f_ssl());
	  if (!ssl_bio)
	    throw OpenSSLException("OpenSSLContext::SSL: BIO_new BIO_f_ssl failed");
	  ct_in = mem_bio(ctx.config.frame);
	  ct_out = mem_bio(ctx.config.frame);

	  // set client/server mode
	  if (ctx.config.mode.is_server())
	    SSL_set_accept_state(ssl);
	  else if (ctx.config.mode.is_client())
	    SSL_set_connect_state(ssl);
	  else
	    OPENVPN_THROW(ssl_context_error, "OpenSSLContext::SSL: unknown client/server mode");

	  // effect SSL/BIO linkage
	  ssl_bio_linkage = true; // after this point, no need to explicitly BIO_free ct_in/ct_out
	  SSL_set_bio (ssl, ct_in, ct_out);
	  BIO_set_ssl (ssl_bio, ssl, BIO_NOCLOSE);
	}
	catch (...)
	  {
	    ssl_erase();
	    throw;
	  }
      }

      // Print a one line summary of SSL/TLS session handshake.
      static std::string ssl_handshake_details (const ::SSL *c_ssl)
      {
	std::ostringstream os;

	const SSL_CIPHER *ciph = SSL_get_current_cipher (c_ssl);
	os << SSL_get_version (c_ssl) << ", cipher " << SSL_CIPHER_get_version (ciph) << ' ' << SSL_CIPHER_get_name (ciph);

	::X509 *cert = SSL_get_peer_certificate (c_ssl);
	if (cert != NULL)
	  {
	    EVP_PKEY *pkey = X509_get_pubkey (cert);
	    if (pkey != NULL)
	      {
		if (pkey->type == EVP_PKEY_RSA && pkey->pkey.rsa != NULL && pkey->pkey.rsa->n != NULL)
		  os << ", " << BN_num_bits (pkey->pkey.rsa->n) << " bit RSA";
#ifndef OPENSSL_NO_DSA
		else if (pkey->type == EVP_PKEY_DSA && pkey->pkey.dsa != NULL && pkey->pkey.dsa->p != NULL)
		  os << ", " << BN_num_bits (pkey->pkey.dsa->p) << " bit DSA";
#endif
		EVP_PKEY_free (pkey);
	      }
	    X509_free (cert);
	  }
	return os.str();
      }

      void ssl_clear()
      {
	ssl_bio_linkage = false;
	ssl = NULL;
	ssl_bio = NULL;
	ct_in = NULL;
	ct_out = NULL;
	overflow = false;
      }

      void ssl_erase()
      {
	if (!ssl_bio_linkage)
	  {
	    if (ct_in)
	      BIO_free(ct_in);
	    if (ct_out)
	      BIO_free(ct_out);
	  }
	if (ssl_bio)
	  BIO_free_all(ssl_bio);
	if (ssl)
	  SSL_free(ssl);
	ssl_clear();
      }

      static BIO* mem_bio(const Frame::Ptr& frame)
      {
	BIO *bio = BIO_new(bmq_stream::BIO_s_memq());
	if (!bio)
	  throw OpenSSLException("OpenSSLContext::SSL: BIO_new failed on bmq_stream");
	bmq_stream::memq_from_bio(bio)->set_frame(frame);
	return bio;
      }

      ::SSL *ssl;	   // OpenSSL SSL object
      BIO *ssl_bio;        // read/write cleartext from here
      BIO *ct_in;          // write ciphertext to here
      BIO *ct_out;         // read ciphertext from here
      bool ssl_bio_linkage;
      bool overflow;
    };

  private:
    class ExternalPKIImpl {
    public:
      ExternalPKIImpl(SSL_CTX* ssl_ctx, ::X509* cert, ExternalPKIBase* external_pki_arg)
	: external_pki(external_pki_arg), n_errors(0)
      {
	RSA *rsa = NULL;
	RSA_METHOD *rsa_meth = NULL;
	RSA *pub_rsa = NULL;
	const char *errtext = "";

	/* allocate custom RSA method object */
	rsa_meth = new RSA_METHOD;
	std::memset(rsa_meth, 0, sizeof(RSA_METHOD));
	rsa_meth->name = "OpenSSLContext::ExternalPKIImpl private key RSA Method";
	rsa_meth->rsa_pub_enc = rsa_pub_enc;
	rsa_meth->rsa_pub_dec = rsa_pub_dec;
	rsa_meth->rsa_priv_enc = rsa_priv_enc;
	rsa_meth->rsa_priv_dec = rsa_priv_dec;
	rsa_meth->init = NULL;
	rsa_meth->finish = rsa_finish;
	rsa_meth->flags = RSA_METHOD_FLAG_NO_CHECK;
	rsa_meth->app_data = (char *)this;

	/* allocate RSA object */
	rsa = RSA_new();
	if (rsa == NULL)
	  {
	    SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
	    errtext = "RSA_new";
	    goto err;
	  }

	/* get the public key */
	if (cert->cert_info->key->pkey == NULL) /* NULL before SSL_CTX_use_certificate() is called */
	  {
	    errtext = "pkey is NULL";
	    goto err;
	  }
	pub_rsa = cert->cert_info->key->pkey->pkey.rsa;

	/* initialize RSA object */
	rsa->n = BN_dup(pub_rsa->n);
	rsa->flags |= RSA_FLAG_EXT_PKEY;
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
	      free(rsa_meth);
	  }
	OPENVPN_THROW(OpenSSLException, "OpenSSLContext::ExternalPKIImpl: " << errtext);
      }

      unsigned int get_n_errors() const { return n_errors; }

    private:
      OPENVPN_EXCEPTION(openssl_external_pki);

      /* called at RSA_free */
      static int rsa_finish(RSA *rsa)
      {
	free ((void*)rsa->meth);
	rsa->meth = NULL;
	return 1;
      }

      /* sign arbitrary data */
      static int rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
      {
	ExternalPKIImpl* self = (ExternalPKIImpl*)rsa->meth->app_data;

	try {
	  if (padding != RSA_PKCS1_PADDING)
	    {
	      RSAerr (RSA_F_RSA_EAY_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
	      throw openssl_external_pki("bad padding size");
	    }

	  /* convert 'from' to base64 */
	  ConstBuffer from_buf(from, flen, true);
	  const std::string from_b64 = base64->encode(from_buf);

	  /* get signature */
	  std::string sig_b64;
	  const bool status = self->external_pki->sign("RSA_RAW", from_b64, sig_b64);
	  if (!status)
	    throw openssl_external_pki("could not obtain signature");

	  /* decode base64 signature to binary */
	  const int len = RSA_size(rsa);
	  Buffer sig(to, len, false);
	  base64->decode(sig, sig_b64);

	  /* verify length */
	  if (sig.size() != len)
	    throw openssl_external_pki("incorrect signature length");

	  /* return length of signature */
	  return len;
	}
	catch (const std::exception& e)
	  {
	    OPENVPN_LOG("OpenSSLContext::ExternalPKIImpl::rsa_priv_enc: " << e.what());
	    ++self->n_errors;
	    return -1;
	  }
      }

      static void not_implemented(RSA *rsa)
      {
	ExternalPKIImpl* self = (ExternalPKIImpl*)rsa->meth->app_data;
	++self->n_errors;
      }

      /* encrypt */
      static int rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
      {
	not_implemented(rsa);
	return -1;
      }

      /* verify arbitrary data */
      static int
      rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
      {
	not_implemented(rsa);
	return -1;
      }

      /* decrypt */
      static int
      rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
      {
	not_implemented(rsa);
	return -1;
      }

      ExternalPKIBase* external_pki;
      unsigned int n_errors;
    };

    /////// start of main class implementation

  public:
    explicit OpenSSLContext(const Config& config_arg)
      : config(config_arg), ctx(NULL), epki(NULL)
    {
      try
	{
	  // Create new SSL_CTX for server or client mode
	  const bool ssl23 = (config.force_aes_cbc_ciphersuites || (config.tls_version_min > TLSVersion::UNDEF));
	  if (config.mode.is_server())
	    {
	      ctx = SSL_CTX_new(ssl23 ? SSLv23_server_method() : TLSv1_server_method());
	      if (ctx == NULL)
		throw OpenSSLException("OpenSSLContext: SSL_CTX_new failed for server method");

	      // Set DH object
	      if (!config.dh.defined())
		OPENVPN_THROW(ssl_context_error, "OpenSSLContext: DH not defined");
	      if (!SSL_CTX_set_tmp_dh(ctx, config.dh.obj()))
		throw OpenSSLException("OpenSSLContext: SSL_CTX_set_tmp_dh failed");
	    }
	  else if (config.mode.is_client())
	    {
	      ctx = SSL_CTX_new(ssl23 ? SSLv23_client_method() : TLSv1_client_method());
	      if (ctx == NULL)
		throw OpenSSLException("OpenSSLContext: SSL_CTX_new failed for client method");
	    }
	  else
	    OPENVPN_THROW(ssl_context_error, "OpenSSLContext: unknown config.mode");

	  // Set SSL options
	  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	  SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
	  long sslopt = SSL_OP_SINGLE_DH_USE | SSL_OP_NO_TICKET;
	  if (ssl23)
	    {
	      sslopt |= SSL_OP_NO_SSLv2;
	      if (!config.force_aes_cbc_ciphersuites)
	        {
		  sslopt |= SSL_OP_NO_SSLv3;
		  if (config.tls_version_min > TLSVersion::V1_0)
		    sslopt |= SSL_OP_NO_TLSv1;
#                 ifdef SSL_OP_NO_TLSv1_1
		    if (config.tls_version_min > TLSVersion::V1_1)
		      sslopt |= SSL_OP_NO_TLSv1_1;
#                 endif
#                 ifdef SSL_OP_NO_TLSv1_2
		    if (config.tls_version_min > TLSVersion::V1_2)
		      sslopt |= SSL_OP_NO_TLSv1_2;
#                 endif
	        }
	    }
	  SSL_CTX_set_options(ctx, sslopt);

	  if (config.force_aes_cbc_ciphersuites)
	    {
	      if (!SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA"))
		OPENVPN_THROW(ssl_context_error, "OpenSSLContext: SSL_CTX_set_cipher_list failed for force_aes_cbc_ciphersuites");
	    }

	  if (config.local_cert_enabled)
	    {
	      // Set certificate
	      if (!config.cert.defined())
		OPENVPN_THROW(ssl_context_error, "OpenSSLContext: cert not defined");
	      if (SSL_CTX_use_certificate(ctx, config.cert.obj()) != 1)
		throw OpenSSLException("OpenSSLContext: SSL_CTX_use_certificate failed");

	      // Set private key
	      if (config.external_pki)
		{
		  epki = new ExternalPKIImpl(ctx, config.cert.obj(), config.external_pki);
		}
	      else
		{
		  if (!config.pkey.defined())
		    OPENVPN_THROW(ssl_context_error, "OpenSSLContext: private key not defined");
		  if (SSL_CTX_use_PrivateKey(ctx, config.pkey.obj()) != 1)
		    throw OpenSSLException("OpenSSLContext: SSL_CTX_use_PrivateKey failed");

		  // Check cert/private key compatibility
		  if (!SSL_CTX_check_private_key(ctx))
		    throw OpenSSLException("OpenSSLContext: private key does not match the certificate");
		}

	      // Set extra certificates that are part of our own certificate
	      // chain but shouldn't be included in the verify chain.
	      if (config.extra_certs.defined())
		{
		  for (OpenSSLPKI::X509List::const_iterator i = config.extra_certs.begin(); i != config.extra_certs.end(); ++i)
		    {
		      if (SSL_CTX_add_extra_chain_cert(ctx, (*i)->obj_dup()) != 1)
			throw OpenSSLException("OpenSSLContext: SSL_CTX_add_extra_chain_cert failed");
		    }
		}
	    }

	  // Set CAs/CRLs
	  if (!config.ca.certs.defined())
	    OPENVPN_THROW(ssl_context_error, "OpenSSLContext: CA not defined");
	  update_trust(config.ca);

	  // keep a reference to this in ctx, for use by verify callback
	  ctx->app_verify_arg = this;

	  // Show handshake debugging info
	  if (config.ssl_debug_level)
	    SSL_CTX_set_info_callback (ctx, info_callback);
	}
      catch (...)
	{
	  erase();
	  throw;
	}
    }

    SSL::Ptr ssl() const { return SSL::Ptr(new SSL(*this)); }

    void update_trust(const CertCRLList& cc)
    {
      OpenSSLPKI::X509Store store(cc);
      SSL_CTX_set_cert_store(ctx, store.move());
    }

    ~OpenSSLContext()
    {
      erase();
    }

    const Mode& mode() const { return config.mode; }
 
  private:
    // ns-cert-type verification

    bool ns_cert_type_defined() const
    {
      return config.ns_cert_type != NSCert::NONE;
    }

    bool verify_ns_cert_type(const ::X509* cert) const
    {
      if (config.ns_cert_type == NSCert::SERVER)
	return (cert->ex_flags & EXFLAG_NSCERT) && (cert->ex_nscert & NS_SSL_SERVER);
      else if (config.ns_cert_type == NSCert::CLIENT)
	return (cert->ex_flags & EXFLAG_NSCERT) && (cert->ex_nscert & NS_SSL_CLIENT);
      else
	return true;
    }

    // remote-cert-ku verification

    bool x509_cert_ku_defined() const
    {
      return config.ku.size() > 0;
    }

    bool verify_x509_cert_ku(::X509 *cert) const
    {
      bool found = false;
      ASN1_BIT_STRING *ku = (ASN1_BIT_STRING *)X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);

      if (ku)
	{
	  // Extract key usage bits
	  unsigned int nku = 0;
	  {
	    for (int i = 0; i < 8; i++)
	      {
		if (ASN1_BIT_STRING_get_bit(ku, i))
		  nku |= 1 << (7 - i);
	      }
	  }

	  // Fixup if no LSB bits
	  if ((nku & 0xff) == 0)
	    nku >>= 8;

	  // Validating certificate key usage
	  {
	    for (std::vector<unsigned int>::const_iterator i = config.ku.begin(); i != config.ku.end(); ++i)
	      {
		if (nku == *i)
		  {
		    found = true;
		    break;
		  }
	      }
	  }

	  ASN1_BIT_STRING_free(ku);
	}
      return found;
    }

    // remote-cert-eku verification

    bool x509_cert_eku_defined() const
    {
      return !config.eku.empty();
    }

    bool verify_x509_cert_eku(::X509 *cert) const
    {
      bool found = false;
      EXTENDED_KEY_USAGE *eku = (EXTENDED_KEY_USAGE *)X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);

      if (eku)
	{
	  // Validating certificate extended key usage
	  for (int i = 0; !found && i < sk_ASN1_OBJECT_num(eku); i++)
	    {
	      ASN1_OBJECT *oid = sk_ASN1_OBJECT_value(eku, i);
	      char oid_str[256];

	      if (!found && OBJ_obj2txt(oid_str, sizeof(oid_str), oid, 0) != -1)
		{
		  // Compare EKU against string
		  if (config.eku == oid_str)
		    found = true;
		}

	      if (!found && OBJ_obj2txt(oid_str, sizeof(oid_str), oid, 1) != -1)
		{
		  // Compare EKU against OID
		  if (config.eku == oid_str)
		    found = true;
		}
	    }

	  sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
	}
      return found;
    }


    static std::string x509_get_subject(::X509 *cert)
    {
      ScopedPtr<char, OpenSSLFree> subject(X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0));
      if (subject.defined())
	return std::string(subject.get());
      else
	return std::string("");
    }

    static std::string x509_get_field(::X509 *cert, const int nid)
    {
      static const char nullc = '\0';
      std::string ret;
      X509_NAME *x509_name = X509_get_subject_name(cert);
      int i = X509_NAME_get_index_by_NID(x509_name, nid, -1);
      if (i >= 0)
	{
	  X509_NAME_ENTRY *ent = X509_NAME_get_entry(x509_name, i);
	  if (ent)
	    {
	      ASN1_STRING *val = X509_NAME_ENTRY_get_data(ent);
	      unsigned char *buf;
	      buf = (unsigned char *)1; // bug in OpenSSL 0.9.6b ASN1_STRING_to_UTF8 requires this workaround
	      if (ASN1_STRING_to_UTF8 (&buf, val) > 0)
		{
		  ret = (char *)buf;
		  OPENSSL_free (buf);
		}
	    }
	}
      else
	{
	  i = X509_get_ext_by_NID(cert, nid, -1);
	  if (i >= 0)
	    {
	      X509_EXTENSION *ext = X509_get_ext(cert, i);
	      if (ext)
		{
		  BIO *bio = BIO_new(BIO_s_mem());
		  if (bio)
		    {
		      if (X509V3_EXT_print(bio, ext, 0, 0))
			{
			  if (BIO_write(bio, &nullc, 1) == 1)
			    {
			      char *str;
			      BIO_get_mem_data(bio, &str);
			      ret = (char *)str;
			    }
			}
		      BIO_free(bio);
		    }
		}
	    }
	}
      return ret;
    }

    static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
    {
      // get the SSL object
      ::SSL* ssl = (::SSL*) X509_STORE_CTX_get_ex_data (ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

      // get this
      const OpenSSLContext* self = (OpenSSLContext*) ssl->ctx->app_verify_arg;

      // log subject
      const std::string subject = x509_get_subject(ctx->current_cert);
      if (!subject.empty())
	OPENVPN_LOG_SSL("VERIFY "
			<< (preverify_ok ? "OK" : "FAIL")
			<< ": depth=" << ctx->error_depth
			<< ", " << subject);

      // leaf-cert verification
      if (ctx->error_depth == 0)
	{
	  // verify ns-cert-type
	  if (self->ns_cert_type_defined() && !self->verify_ns_cert_type(ctx->current_cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad ns-cert-type in leaf certificate");
	      preverify_ok = false;
	    }

	  // verify X509 key usage
	  if (self->x509_cert_ku_defined() && !self->verify_x509_cert_ku(ctx->current_cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 key usage in leaf certificate");
	      preverify_ok = false;
	    }

	  // verify X509 extended key usage
	  if (self->x509_cert_eku_defined() && !self->verify_x509_cert_eku(ctx->current_cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 extended key usage in leaf certificate");
	      preverify_ok = false;
	    }

	  // verify tls-remote
	  if (!self->config.tls_remote.empty())
	    {
	      const std::string subj = TLSRemote::sanitize_x509_name(subject);
	      const std::string common_name = TLSRemote::sanitize_common_name(x509_get_field(ctx->current_cert, NID_commonName));
	      TLSRemote::log(self->config.tls_remote, subj, common_name);
	      if (!TLSRemote::test(self->config.tls_remote, subj, common_name))
		{
		  OPENVPN_LOG_SSL("VERIFY FAIL -- tls-remote match failed");
		  preverify_ok = false;
		}
	    }
	}

      return preverify_ok;
    }

    // Print debugging information on SSL/TLS session negotiation.
    static void info_callback (const ::SSL *s, int where, int ret)
    {
      if (where & SSL_CB_LOOP)
	{
	  OPENVPN_LOG_SSL("SSL state (" << (where & SSL_ST_CONNECT ? "connect" : where & SSL_ST_ACCEPT ? "accept" : "undefined") << "): " << SSL_state_string_long(s));
	}
      else if (where & SSL_CB_ALERT)
	{
	  OPENVPN_LOG_SSL("SSL alert (" << (where & SSL_CB_READ ? "read" : "write") << "): " << SSL_alert_type_string_long(ret) << ": " << SSL_alert_desc_string_long(ret));
	}
    }

    void erase()
    {
      if (epki)
	{
	  delete epki;
	  epki = NULL;
	}
      if (ctx)
	{
	  SSL_CTX_free(ctx);
	  ctx = NULL;
	}
    }

    Config config;
    SSL_CTX* ctx;
    ExternalPKIImpl* epki;
  };

}

#endif
