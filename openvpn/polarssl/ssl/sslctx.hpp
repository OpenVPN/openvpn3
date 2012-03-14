#ifndef OPENVPN_POLARSSL_SSL_SSLCTX_H
#define OPENVPN_POLARSSL_SSL_SSLCTX_H

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

#include <openvpn/polarssl/pki/x509cert.hpp>
#include <openvpn/polarssl/pki/rsactx.hpp>
#include <openvpn/polarssl/util/rand.hpp>
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
  class PolarSSLContext : public RC<thread_unsafe_refcount>
  {
  public:
    typedef boost::intrusive_ptr<PolarSSLContext> Ptr;

    OPENVPN_SIMPLE_EXCEPTION(ssl_ciphertext_in_overflow);

    enum {
      MAX_CIPHERTEXT_IN = 64
    };

    // The data needed to construct a PolarSSLContext.
    struct Config
    {
      enum {
	DEBUG = 1<<0,
      };
      typedef unsigned int Flags;

      enum CertType {
	CERT_TYPE_NONE,
	CERT_TYPE_NS_CLIENT,
	CERT_TYPE_NS_SERVER
      };

      Config() : external_pki(NULL),
		 flags(0),
		 cert_type(CERT_TYPE_NONE) {}

      Mode mode;
      PolarSSLPKI::X509Cert::Ptr crt_chain;  // local cert chain (including client cert + extra certs)
      PolarSSLPKI::X509Cert::Ptr ca_chain;   // CA chain for remote verification
      PolarSSLPKI::RSAContext::Ptr priv_key; // private key
      ExternalPKIBase* external_pki;
      Frame::Ptr frame;
      Flags flags;
      CertType cert_type;
      PolarSSLRandom::Ptr rng; // random data source

      void enable_debug()
      {
	flags |= DEBUG;
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
	p->parse(key_txt, "private key");
	priv_key = p;
      }

#if 0 // fixme -- implement PolarSSL DH
      void load_dh(const std::string& dh_txt)
      {
      }
#endif

      void load(const OptionList& opt)
      {
	// client/server
	mode = opt.exists("client") ? Mode(Mode::CLIENT) : Mode(Mode::SERVER);

	// ca
	{
	  const std::string& ca_txt = opt.get("ca", 1);
	  load_ca(ca_txt);
	}

	// cert/extra-certs
	{
	  const std::string& cert_txt = opt.get("cert", 1);
	  const std::string& ec_txt = opt.get_optional("extra-certs", 1);
	  load_cert(cert_txt, ec_txt);
	}

	// private key
	if (!external_pki)
	  {
	    const std::string& key_txt = opt.get("key", 1);
	    load_private_key(key_txt);
	  }

#if 0 // fixme -- implement PolarSSL DH
	// DH
	if (mode.is_server())
	  {
	    const std::string& dh_txt = opt.get("dh", 1);
	    load_dh(dh_txt);
	  }
#endif

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

	// unsupported cert type checkers
	{
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
    // Normally instantiated by PolarSSLContext::ssl().
    class SSL : public RC<thread_unsafe_refcount>
    {
      // read/write callback errors
      enum {
	// assumes that PolarSSL user-defined errors may start at -0x8000
	CT_WOULD_BLOCK = -0x8000,
	CT_INTERNAL_ERROR = -0x8001
      };

    public:
      typedef boost::intrusive_ptr<SSL> Ptr;

      // special return value from read functions -- indicates
      // that no cleartext data is available now (until more
      // ciphertext is pushed into the SSL engine)
      enum {
	SHOULD_RETRY = -1
      };

      SSL(const PolarSSLContext* ctx)
      {
	clear();
	try {
	  const Config& c = ctx->config;
	  int status;

	  // init SSL object
	  ssl = new ssl_context;
	  std::memset(ssl, 0, sizeof(ssl));
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
	  ssl_set_verify(ssl, verify_callback, (void *)ctx);

	  // allocate session object, but don't support SSL-level session resume
	  sess = new ssl_session;
	  std::memset(sess, 0, sizeof(sess));
	  ssl_set_session(ssl, 0, 0, sess);

	  // set list of allowed ciphersuites
	  ssl_set_ciphersuites(ssl, (int *)polarssl_ctx_private::default_ciphersuites); // fixme -- fix PolarSSL to not require cast

	  // set CA chain
	  if (c.ca_chain)
	    ssl_set_ca_chain(ssl, c.ca_chain->get(), NULL, NULL);
	  else
	    throw PolarSSLException("CA chain not defined");

	  // set our own certificate, supporting chain (i.e. extra-certs), and private key
	  if (c.crt_chain && c.priv_key)
	    ssl_set_own_cert(ssl, c.crt_chain->get(), c.priv_key->get());
	  else
	    throw PolarSSLException("cert and/or private key is undefined");

	  // fixme -- set pkcs11

	  // fixme -- set DH

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
	}
	catch (...)
	  {
	    erase();
	    throw;
	  }
      }

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
	return self->rng->rand_bytes_noexcept(data, len);
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
      PolarSSLRandom::Ptr rng; // random data source
      bool overflow;
      MemQStream ct_in;    // write ciphertext to here
      MemQStream ct_out;   // read ciphertext from here
    };

    // begin main class

    explicit PolarSSLContext(const Config& config_arg)
    {
      config = config_arg;
    }

    SSL::Ptr ssl() const { return SSL::Ptr(new SSL(this)); }

    const Mode& mode() const { return config.mode; }
 
    ~PolarSSLContext()
    {
      erase();
    }

  private:
    bool verify_ns_cert_type(const x509_cert *cert) const
    {
      if (config.cert_type == Config::CERT_TYPE_NS_SERVER)
	return bool(cert->ns_cert_type & NS_CERT_TYPE_SSL_SERVER);
      else if (config.cert_type == Config::CERT_TYPE_NS_CLIENT)
	return bool(cert->ns_cert_type & NS_CERT_TYPE_SSL_CLIENT);
      else
	return true;
    }

    static int verify_callback(void *arg, x509_cert *cert, int depth, int preverify_ok)
    {
      PolarSSLContext *self = (PolarSSLContext *)arg;

      OPENVPN_LOG_SSL("VERIFY "
		      << (preverify_ok ? "OK" : "FAIL")
		      << ": depth=" << depth
		      << std::endl << cert_info(cert));

      // verify ns-cert-type
      if (depth == 0 && !self->verify_ns_cert_type(cert))
	{
	  OPENVPN_LOG("VERIFY FAIL -- bad ns-cert-type in leaf certificate");
	  preverify_ok = false;
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

    Config config;
  };

} // namespace openvpn

#endif
