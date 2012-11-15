//
//  sslctx.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

#ifndef OPENVPN_POLARSSL_SSL_SSLCTX_H
#define OPENVPN_POLARSSL_SSL_SSLCTX_H

#include <vector>
#include <string>
#include <cstring>
#include <sstream>

#include <polarssl/ssl.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/mode.hpp>
#include <openvpn/common/options.hpp>
#include <openvpn/common/scoped_ptr.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/frame/memq_stream.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/pki/cclist.hpp>
#include <openvpn/pki/epkibase.hpp>
#include <openvpn/ssl/kuparse.hpp>
#include <openvpn/ssl/nscert.hpp>

#include <openvpn/polarssl/pki/x509cert.hpp>
#include <openvpn/polarssl/pki/dh.hpp>
#include <openvpn/polarssl/pki/rsactx.hpp>
#include <openvpn/polarssl/util/error.hpp>

// An SSL Context is essentially a configuration that can be used
// to generate an arbitrary number of actual SSL connections objects.

// PolarSSLContext is an SSL Context implementation that uses the
// PolarSSL library as a backend.

namespace openvpn {

  namespace polarssl_ctx_private {
    static const int default_ciphersuites[] = // CONST GLOBAL
      {
	SSL_EDH_RSA_AES_256_SHA,
	SSL_EDH_RSA_AES_128_SHA,
	0
      };
  };

  // Represents an SSL configuration that can be used
  // to instantiate actual SSL sessions.
  template <typename RAND_API>
  class PolarSSLContext : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<PolarSSLContext> Ptr;

    OPENVPN_SIMPLE_EXCEPTION(ssl_ciphertext_in_overflow);
    OPENVPN_EXCEPTION(polarssl_external_pki);

    enum {
      MAX_CIPHERTEXT_IN = 64
    };

    // The data needed to construct a PolarSSLContext.
    struct Config
    {
      enum {
	SSL_DEBUG_FLAG = 1<<0,
      };
      typedef unsigned int Flags;

      Config() : external_pki(NULL),
		 flags(0),
		 ns_cert_type(NSCert::NONE) {}

      Mode mode;
      PolarSSLPKI::X509Cert::Ptr crt_chain;  // local cert chain (including client cert + extra certs)
      PolarSSLPKI::X509Cert::Ptr ca_chain;   // CA chain for remote verification
      PolarSSLPKI::RSAContext::Ptr priv_key; // private key
      std::string priv_key_pwd;              // private key password
      PolarSSLPKI::DH::Ptr dh;               // diffie-hellman parameters
      ExternalPKIBase* external_pki;
      Frame::Ptr frame;
      Flags flags;
      NSCert::Type ns_cert_type;
      std::vector<unsigned int> ku; // if defined, peer cert X509 key usage must match one of these values
      std::string eku;              // if defined, peer cert X509 extended key usage must match this OID/string
      typename RAND_API::Ptr rng;   // random data source

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
	PolarSSLPKI::X509Cert::Ptr c = new PolarSSLPKI::X509Cert();
	c->parse(ca_txt, "ca");
	ca_chain = c;
      }

      void load_cert(const std::string& cert_txt)
      {
	PolarSSLPKI::X509Cert::Ptr c = new PolarSSLPKI::X509Cert();
	c->parse(cert_txt, "cert");
	crt_chain = c;
      }

      void load_cert(const std::string& cert_txt, const std::string& extra_certs_txt)
      {
	PolarSSLPKI::X509Cert::Ptr c = new PolarSSLPKI::X509Cert();
	c->parse(cert_txt, "cert");
	if (!extra_certs_txt.empty())
	  c->parse(extra_certs_txt, "extra-certs");
	crt_chain = c;
      }

      void load_private_key(const std::string& key_txt)
      {
	PolarSSLPKI::RSAContext::Ptr p = new PolarSSLPKI::RSAContext();
	p->parse(key_txt, "config", priv_key_pwd);
	priv_key = p;
      }

      void load_dh(const std::string& dh_txt)
      {
	PolarSSLPKI::DH::Ptr mydh = new PolarSSLPKI::DH();
	mydh->parse(dh_txt, "server-config");
	dh = mydh;
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

	// cert/extra-certs
	{
	  const std::string& cert_txt = opt.get("cert", 1, Option::MULTILINE);
	  const std::string ec_txt = opt.cat("extra-certs");
	  load_cert(cert_txt, ec_txt);
	}

	// private key
	if (!external_pki)
	  {
	    const std::string& key_txt = opt.get("key", 1, Option::MULTILINE);
	    load_private_key(key_txt);
	  }

	// DH
	if (mode.is_server())
	  {
	    const std::string& dh_txt = opt.get("dh", 1, Option::MULTILINE);
	    load_dh(dh_txt);
	  }

	// parse ns-cert-type
	ns_cert_type = NSCert::ns_cert_type(opt);

	// parse remote-cert-x options
	KUParse::remote_cert_tls(opt, ku, eku);
	KUParse::remote_cert_ku(opt, ku);
	KUParse::remote_cert_eku(opt, eku);

	// unsupported cert verification options
	{
	  if (opt.exists("tls-remote"))
	    throw option_error("tls-remote not supported");
	}
      }
    };

    // Represents an actual SSL session.
    // Normally instantiated by PolarSSLContext::ssl().
    class SSL : public RC<thread_unsafe_refcount>
    {
      // read/write callback errors
      enum {
	// assumes that PolarSSL user-defined errors may start at -0x8000
	CT_WOULD_BLOCK = -0x8000,
	CT_INTERNAL_ERROR = -0x8001
      };

      friend class PolarSSLContext;

    public:
      typedef boost::intrusive_ptr<SSL> Ptr;

      // special return value from read functions -- indicates
      // that no cleartext data is available now (until more
      // ciphertext is pushed into the SSL engine)
      enum {
	SHOULD_RETRY = -1
      };

      void start_handshake()
      {
	ssl_handshake(ssl);
      }

      ssize_t write_cleartext_unbuffered(const void *data, const size_t size)
      {
	const int status = ssl_write(ssl, (const unsigned char*)data, size);
	if (status < 0)
	  {
	    if (status == CT_WOULD_BLOCK)
	      return SHOULD_RETRY;
	    else if (status == CT_INTERNAL_ERROR)
	      throw PolarSSLException("SSL write: internal error");
	    else
	      throw PolarSSLException("SSL write error", status);
	  }
	else
	  return status;
      }

      ssize_t read_cleartext(void *data, const size_t capacity)
      {
	if (!overflow)
	  {
	    const int status = ssl_read(ssl, (unsigned char*)data, capacity);
	    if (status < 0)
	      {
		if (status == CT_WOULD_BLOCK)
		  return SHOULD_RETRY;
		else if (status == CT_INTERNAL_ERROR)
		  throw PolarSSLException("SSL read: internal error");
		else
		  throw PolarSSLException("SSL read error", status);
	      }
	    else
	      return status;
	  }
	else
	  throw ssl_ciphertext_in_overflow();
      }

      bool write_ciphertext_ready() const {
	return !ct_in.empty();
      }

      void write_ciphertext(const BufferPtr& buf)
      {
	if (ct_in.size() < MAX_CIPHERTEXT_IN)
	  ct_in.write_buf(buf);
	else
	  overflow = true;
      }

      bool read_ciphertext_ready() const {
	return !ct_out.empty();
      }

      BufferPtr read_ciphertext()
      {
	return ct_out.read_buf();
      }

      std::string ssl_handshake_details() const
      {
	return ssl_get_version(ssl) + std::string("/") + ssl_get_ciphersuite(ssl);
      }

      ~SSL()
      {
	erase();
      }

    private:
      SSL(PolarSSLContext* ctx)
      {
	clear();
	try {
	  const Config& c = ctx->config;
	  int status;

	  // init SSL object
	  ssl = new ssl_context;
	  status = ssl_init(ssl);
	  if (status < 0)
	    throw PolarSSLException("error in ssl_init", status);

	  // set client/server mode
	  if (c.mode.is_server())
	    ssl_set_endpoint(ssl, SSL_IS_SERVER);
	  else if (c.mode.is_client())
	    ssl_set_endpoint(ssl, SSL_IS_CLIENT);
	  else
	    throw PolarSSLException("unknown client/server mode");

	  // peer must present a valid certificate
	  ssl_set_authmode(ssl, SSL_VERIFY_REQUIRED);

	  // set verify callback
	  ssl_set_verify(ssl, verify_callback, ctx);

	  // allocate session object, but don't support SSL-level session resume
	  sess = new ssl_session;
	  std::memset(sess, 0, sizeof(*sess));
	  ssl_set_session(ssl, 0, 0, sess);

	  // set list of allowed ciphersuites
	  ssl_set_ciphersuites(ssl, polarssl_ctx_private::default_ciphersuites);

	  // set CA chain
	  if (c.ca_chain)
	    ssl_set_ca_chain(ssl, c.ca_chain->get(), NULL, NULL);
	  else
	    throw PolarSSLException("CA chain not defined");

	  if (c.external_pki)
	    {
	      // set our own certificate, supporting chain (i.e. extra-certs), and external private key
	      if (c.crt_chain)
		ssl_set_own_cert_pkcs11(ssl, c.crt_chain->get(), &ctx->p11);
	      else
		throw PolarSSLException("cert is undefined");
	    }
	  else
	    {
	      // set our own certificate, supporting chain (i.e. extra-certs), and private key
	      if (c.crt_chain && c.priv_key)
		ssl_set_own_cert(ssl, c.crt_chain->get(), c.priv_key->get());
	      else
		throw PolarSSLException("cert and/or private key is undefined");
	    }

	  // set DH
	  if (c.dh)
	    {
	      status = ssl_set_dh_param_ctx(ssl, c.dh->get());
	      if (status < 0)
		throw PolarSSLException("error in ssl_set_dh_param_ctx", status);
	    }

	  // configure ciphertext buffers
	  ct_in.set_frame(c.frame);
	  ct_out.set_frame(c.frame);

	  // set BIO
	  ssl_set_bio(ssl, ct_read_func, this, ct_write_func, this);

	  // set RNG
	  if (c.rng)
	    {
	      rng = c.rng;
	      ssl_set_rng(ssl, rng_callback, this);
	    }
	  else
	    throw PolarSSLException("RNG not defined");

	  // set debug callback
	  if (c.flags & Config::SSL_DEBUG_FLAG)
	    ssl_set_dbg(ssl, dbg_callback, this);
	}
	catch (...)
	  {
	    erase();
	    throw;
	  }
      }

      // cleartext read callback
      static int ct_read_func(void *arg, unsigned char *data, size_t length)
      {
	try {
	  SSL *self = (SSL *)arg;
	  const size_t actual = self->ct_in.read(data, length);
	  return actual > 0 ? actual : CT_WOULD_BLOCK;
	}
	catch (...)
	  {
	    return CT_INTERNAL_ERROR;
	  }
      }

      // cleartext write callback
      static int ct_write_func(void *arg, const unsigned char *data, size_t length)
      {
	try {
	  SSL *self = (SSL *)arg;
	  self->ct_out.write(data, length);
	  return length;
	}
	catch (...)
	  {
	    return CT_INTERNAL_ERROR;
	  }
      }

      // RNG callback -- return random data to PolarSSL
      static int rng_callback(void *arg, unsigned char *data, size_t len)
      {
	SSL *self = (SSL *)arg;
	return self->rng->rand_bytes_noexcept(data, len) ? 0 : -1; // using -1 as a general-purpose PolarSSL error code
      }

      static void dbg_callback(void *arg, int level, const char *text)
      {
	if (level <= 1)
	  OPENVPN_LOG_NTNL("PolarSSL[" << level << "]: " << text);
      }

      void clear()
      {
	ssl = NULL;
	sess = NULL;
	overflow = false;
      }

      void erase()
      {
	if (ssl)
	  {
	    ssl_free(ssl);
	    delete ssl;
	  }
	if (sess)
	  delete sess;
	clear();
      }

      ssl_context *ssl;	       // underlying SSL connection object
      ssl_session *sess;       // SSL session (tied to ssl object above)
      typename RAND_API::Ptr rng;       // random data source
      bool overflow;
      MemQStream ct_in;    // write ciphertext to here
      MemQStream ct_out;   // read ciphertext from here
    };

    /////// start of main class implementation

    explicit PolarSSLContext(const Config& config_arg)
    {
      config = config_arg;

      // Verify that cert is defined
      if (!config.crt_chain)
	throw PolarSSLException("cert is undefined");

      // PKCS11 setup (always done, even if non-external-pki)
      p11.parameter = this;
      p11.f_decrypt = epki_decrypt;
      p11.f_sign = epki_sign;
      p11.len = config.crt_chain->get()->rsa.len;
    }

    typename SSL::Ptr ssl() { return typename SSL::Ptr(new SSL(this)); }

    const Mode& mode() const { return config.mode; }
 
    ~PolarSSLContext()
    {
      erase();
    }

  private:
    // ns-cert-type verification

    bool ns_cert_type_defined() const
    {
      return config.ns_cert_type != NSCert::NONE;
    }

    bool verify_ns_cert_type(const x509_cert *cert) const
    {
      if (config.ns_cert_type == NSCert::SERVER)
	return bool(cert->ns_cert_type & NS_CERT_TYPE_SSL_SERVER);
      else if (config.ns_cert_type == NSCert::CLIENT)
	return bool(cert->ns_cert_type & NS_CERT_TYPE_SSL_CLIENT);
      else
	return false;
    }

    // remote-cert-ku verification

    bool x509_cert_ku_defined() const
    {
      return config.ku.size() > 0;
    }

    bool verify_x509_cert_ku(const x509_cert *cert)
    {
      if (cert->ext_types & EXT_KEY_USAGE)
	{
	  const unsigned int ku = cert->key_usage;
	  for (std::vector<unsigned int>::const_iterator i = config.ku.begin(); i != config.ku.end(); ++i)
	    {
	      if (ku == *i)
		return true;
	    }
	}
      return false;
    }

    // remote-cert-eku verification

    bool x509_cert_eku_defined() const
    {
      return !config.eku.empty();
    }

    bool verify_x509_cert_eku(x509_cert *cert)
    {
      if (cert->ext_types & EXT_EXTENDED_KEY_USAGE)
	{
	  x509_sequence *oid_seq = &cert->ext_key_usage;
	  while (oid_seq != NULL)
	    {
	      x509_buf *oid = &oid_seq->buf;

	      // first compare against description
	      {
		const char *oid_str = x509_oid_get_description(oid);
		if (oid_str && config.eku == oid_str)
		  return true;
	      }

	      // next compare against OID numeric string
	      {
		char oid_num_str[256];
		const int status = x509_oid_get_numeric_string(oid_num_str, sizeof(oid_num_str), oid);
		if (status >= 0 && config.eku == oid_num_str)
		  return true;
	      }
	      oid_seq = oid_seq->next;
	    }
	}
      return false;
    }

    static int verify_callback(void *arg, x509_cert *cert, int depth, int preverify_ok)
    {
      PolarSSLContext *self = (PolarSSLContext *)arg;

      OPENVPN_LOG_SSL("VERIFY "
		      << (preverify_ok ? "OK" : "FAIL")
		      << ": depth=" << depth
		      << std::endl << cert_info(cert));

      // leaf-cert verification
      if (depth == 0)
	{
	  // verify ns-cert-type
	  if (self->ns_cert_type_defined() && !self->verify_ns_cert_type(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad ns-cert-type in leaf certificate");
	      preverify_ok = false;
	    }

	  // verify X509 key usage
	  if (self->x509_cert_ku_defined() && !self->verify_x509_cert_ku(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 key usage in leaf certificate");
	      preverify_ok = false;
	    }

	  // verify X509 extended key usage
	  if (self->x509_cert_eku_defined() && !self->verify_x509_cert_eku(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 extended key usage in leaf certificate");
	      preverify_ok = false;
	    }
	}

      return preverify_ok ? 0 : POLARSSL_ERR_SSL_PEER_VERIFY_FAILED;
    }

    static std::string cert_info(const x509_cert *cert, const char *prefix = NULL)
    {
      char buf[512];
      const int size = x509parse_cert_info(buf, sizeof(buf), prefix ? prefix : "", cert);
      if (size >= 0)
	return buf;
      else
	return "error rendering cert";
    }

    void erase()
    {
    }

    static int epki_decrypt(pkcs11_context *ctx,
			    int mode,
			    size_t *olen,
			    const unsigned char *input,
			    unsigned char *output,
			    unsigned int output_max_len)
    {
      OPENVPN_LOG_SSL("PolarSSLContext::epki_decrypt is unimplemented, mode=" << mode
		      << " output_max_len=" << output_max_len);
      return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
    }

    static int epki_sign(pkcs11_context *ctx,
			 int mode,
			 int hash_id,
			 unsigned int hashlen,
			 const unsigned char *hash,
			 unsigned char *sig)
    {
      PolarSSLContext *self = (PolarSSLContext *) ctx->parameter;
      try {
	if (mode == RSA_PRIVATE && hash_id == SIG_RSA_RAW)
	  {
	    /* convert 'hash' to base64 */
	    ConstBuffer from_buf(hash, hashlen, true);
	    const std::string from_b64 = base64->encode(from_buf);

	    /* get signature */
	    std::string sig_b64;
	    const bool status = self->config.external_pki->sign(from_b64, sig_b64);
	    if (!status)
	      throw polarssl_external_pki("could not obtain signature");

	    /* decode base64 signature to binary */
	    const int len = ctx->len;
	    Buffer sigbuf(sig, len, false);
	    base64->decode(sigbuf, sig_b64);

	    /* verify length */
	    if (sigbuf.size() != len)
	      throw polarssl_external_pki("incorrect signature length");

	    /* success */
	    return 0;
	  }
	else
	  {
	    OPENVPN_LOG_SSL("PolarSSLContext::epki_sign unrecognized parameters, mode=" << mode 
			    << " hash_id=" << hash_id << " hashlen=" << hashlen);
	    return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
	  }
      }
      catch (const std::exception& e)
	{
	  OPENVPN_LOG("PolarSSLContext::epki_sign: " << e.what());
	  return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
	}
    }

    Config config;
    pkcs11_context p11;
  };

} // namespace openvpn

#endif
