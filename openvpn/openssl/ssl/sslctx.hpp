//
//  sslctx.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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
#include <openvpn/frame/frame.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/pki/cclist.hpp>
#include <openvpn/pki/epkibase.hpp>
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
      MAX_CIPHERTEXT_IN = 64
    };

    // The data needed to construct an OpenSSLContext.
    struct Config
    {
      enum {
	SSL_DEBUG_FLAG = 1<<0,
      };
      typedef unsigned int Flags;

      enum CertType {
	CERT_TYPE_NONE,
	CERT_TYPE_NS_CLIENT,
	CERT_TYPE_NS_SERVER
      };

      Config() : external_pki(NULL), flags(0), cert_type(CERT_TYPE_NONE) {}

      Mode mode;
      CertCRLList ca;
      OpenSSLPKI::X509 cert;
      OpenSSLPKI::X509List extra_certs;
      OpenSSLPKI::PKey pkey;
      OpenSSLPKI::DH dh; // only needed in server mode
      ExternalPKIBase* external_pki;
      Frame::Ptr frame;
      Flags flags;
      CertType cert_type;

      void enable_debug()
      {
	flags |= SSL_DEBUG_FLAG;
      }

      // if this callback is defined, no private key needs to be loaded
      void set_external_pki_callback(ExternalPKIBase* external_pki_arg)
      {
	external_pki = external_pki_arg;
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
	mode = opt.exists_unique("client") ? Mode(Mode::CLIENT) : Mode(Mode::SERVER);

	// ca
	{
	  const std::string ca_txt = opt.cat("ca");
	  load_ca(ca_txt);
	}

	// cert
	{
	  const std::string& cert_txt = opt.get("cert", 1);
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
	    const std::string& key_txt = opt.get("key", 1);
	    load_private_key(key_txt);
	  }

	// DH
	if (mode.is_server())
	  {
	    const std::string& dh_txt = opt.get("dh", 1);
	    load_dh(dh_txt);
	  }

	// ns-cert-type
	{
	  const Option* o = opt.get_ptr("ns-cert-type");
	  if (o)
	    {
	      const std::string& ct = o->get_optional(1);
	      if (ct == "server")
		cert_type = CERT_TYPE_NS_SERVER;
	      else if (ct == "client")
		cert_type = CERT_TYPE_NS_CLIENT;
	      else
		throw option_error("ns-cert-type must be 'client' or 'server'");
	    }
	}

	// unsupported cert checkers
	{
	  if (opt.get_ptr("tls-remote"))
	    throw option_error("tls-remote not supported");
	  if (opt.get_ptr("remote-cert-tls"))
	    throw option_error("remote-cert-tls not supported");
	  if (opt.get_ptr("remote-cert-ku"))
	    throw option_error("remote-cert-ku not supported");
	  if (opt.get_ptr("remote-cert-eku"))
	    throw option_error("remote-cert-eku not supported");
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
	  ssl = SSL_new(ctx.raw_ctx());
	  if (!ssl)
	    throw OpenSSLException("OpenSSLContext::SSL: SSL_new failed");
	  ssl_bio = BIO_new(BIO_f_ssl());
	  if (!ssl_bio)
	    throw OpenSSLException("OpenSSLContext::SSL: BIO_new BIO_f_ssl failed");
	  ct_in = mem_bio(ctx.frame());
	  ct_out = mem_bio(ctx.frame());

	  // set client/server mode
	  if (ctx.mode().is_server())
	    SSL_set_accept_state(ssl);
	  else if (ctx.mode().is_client())
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
	  const bool status = self->external_pki->sign(from_b64, sig_b64);
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
    explicit OpenSSLContext(const Config& config)
      : ctx_(NULL), epki_(NULL)
    {
      try
	{
	  // Create new SSL_CTX for server or client mode
	  if (config.mode.is_server())
	    {
	      ctx_ = SSL_CTX_new(TLSv1_server_method());
	      if (ctx_ == NULL)
		throw OpenSSLException("OpenSSLContext: SSL_CTX_new failed for server method");

	      // Set DH object
	      if (!config.dh.defined())
		OPENVPN_THROW(ssl_context_error, "OpenSSLContext: DH not defined");
	      if (!SSL_CTX_set_tmp_dh(ctx_, config.dh.obj()))
		throw OpenSSLException("OpenSSLContext: SSL_CTX_set_tmp_dh failed");
	    }
	  else if (config.mode.is_client())
	    {
	      ctx_ = SSL_CTX_new(TLSv1_client_method());
	      if (ctx_ == NULL)
		throw OpenSSLException("OpenSSLContext: SSL_CTX_new failed for client method");
	    }
	  else
	    OPENVPN_THROW(ssl_context_error, "OpenSSLContext: unknown config.mode");

	  // Set SSL options
	  SSL_CTX_set_session_cache_mode(ctx_, SSL_SESS_CACHE_OFF);
	  SSL_CTX_set_options(ctx_, SSL_OP_SINGLE_DH_USE);
	  SSL_CTX_set_verify (ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);

	  // fixme -- support SSL_CTX_set_cipher_list

	  // Set certificate
	  if (!config.cert.defined())
	    OPENVPN_THROW(ssl_context_error, "OpenSSLContext: cert not defined");
	  if (SSL_CTX_use_certificate(ctx_, config.cert.obj()) != 1)
	    throw OpenSSLException("OpenSSLContext: SSL_CTX_use_certificate failed");

	  // Set private key
	  if (config.external_pki)
	    {
	      epki_ = new ExternalPKIImpl(ctx_, config.cert.obj(), config.external_pki);
	    }
	  else
	    {
	      // fixme -- add support for private key encryption
	      if (!config.pkey.defined())
		OPENVPN_THROW(ssl_context_error, "OpenSSLContext: private key not defined");
	      if (SSL_CTX_use_PrivateKey(ctx_, config.pkey.obj()) != 1)
		throw OpenSSLException("OpenSSLContext: SSL_CTX_use_PrivateKey failed");

	      // Check cert/private key compatibility
	      if (!SSL_CTX_check_private_key(ctx_))
		throw OpenSSLException("OpenSSLContext: private key does not match the certificate");
	    }

	  // Set extra certificates that are part of our own certificate
	  // chain but shouldn't be included in the verify chain.
	  if (config.extra_certs.defined())
	    {
	      for (OpenSSLPKI::X509List::const_iterator i = config.extra_certs.begin(); i != config.extra_certs.end(); ++i)
		{
		  if (SSL_CTX_add_extra_chain_cert(ctx_, (*i)->obj_dup()) != 1)
		    throw OpenSSLException("OpenSSLContext: SSL_CTX_add_extra_chain_cert failed");
		}
	    }

	  // Set CAs/CRLs
	  if (!config.ca.certs.defined())
	    OPENVPN_THROW(ssl_context_error, "OpenSSLContext: CA not defined");
	  update_trust(config.ca);

	  // Set required cert type
	  cert_type_ = config.cert_type;

	  // keep a reference to this in ctx, for use by verify callback
	  ctx_->app_verify_arg = this;

	  // Show handshake debugging info
	  if (config.flags & Config::SSL_DEBUG_FLAG)
	    SSL_CTX_set_info_callback (ctx_, info_callback);

	  // Keep a reference to vars so we can hand them off to SSL objects derived from us
	  mode_ = config.mode;
	  flags_ = config.flags;
	  frame_ = config.frame;
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
      SSL_CTX_set_cert_store(ctx_, store.move());
    }

    ~OpenSSLContext()
    {
      erase();
    }

    const Mode& mode() const { return mode_; }
 
  private:
    Config::Flags flags() const { return flags_; }
    const Frame::Ptr& frame() const { return frame_; }
    SSL_CTX* raw_ctx() const { return ctx_; }

    bool verify_ns_cert_type(const ::X509* cert) const
    {
      if (cert_type_ == Config::CERT_TYPE_NS_SERVER)
	return (cert->ex_flags & EXFLAG_NSCERT) && (cert->ex_nscert & NS_SSL_SERVER);
      else if (cert_type_ == Config::CERT_TYPE_NS_CLIENT)
	return (cert->ex_flags & EXFLAG_NSCERT) && (cert->ex_nscert & NS_SSL_CLIENT);
      else
	return true;
    }

    static int verify_callback (int preverify_ok, X509_STORE_CTX *ctx)
    {
      // get the SSL object
      ::SSL* ssl = (::SSL*) X509_STORE_CTX_get_ex_data (ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

      // get this
      OpenSSLContext* self = (OpenSSLContext*) ssl->ctx->app_verify_arg;

      // log subject
      ScopedPtr<char, OpenSSLFree> subject(X509_NAME_oneline(X509_get_subject_name(ctx->current_cert), NULL, 0));
      if (subject.defined())
	OPENVPN_LOG_SSL("VERIFY "
			<< (preverify_ok ? "OK" : "FAIL")
			<< ": depth=" << ctx->error_depth
			<< ", " << subject.get());

      // verify ns-cert-type
      if (ctx->error_depth == 0 && !self->verify_ns_cert_type(ctx->current_cert))
	{
	  OPENVPN_LOG_SSL("VERIFY FAIL -- bad ns-cert-type in leaf certificate");
	  preverify_ok = false;
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
      if (epki_)
	{
	  delete epki_;
	  epki_ = NULL;
	}
      if (ctx_)
	{
	  SSL_CTX_free(ctx_);
	  ctx_ = NULL;
	}
    }

    Mode mode_;
    Config::Flags flags_;
    Config::CertType cert_type_;
    Frame::Ptr frame_;
    SSL_CTX* ctx_;
    ExternalPKIImpl* epki_;
  };

}

#endif
