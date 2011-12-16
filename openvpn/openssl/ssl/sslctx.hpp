#ifndef OPENVPN_OPENSSL_SSL_SSLCTX_H
#define OPENVPN_OPENSSL_SSL_SSLCTX_H

#include <openssl/ssl.h>

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/log/log.hpp>
#include <openvpn/frame/frame.hpp>
#include <openvpn/pki/cclist.hpp>
#include <openvpn/ssl/sslconf.hpp>
#include <openvpn/openssl/util/error.hpp>
#include <openvpn/openssl/pki/x509.hpp>
#include <openvpn/openssl/pki/crl.hpp>
#include <openvpn/openssl/pki/pkey.hpp>
#include <openvpn/openssl/pki/dh.hpp>
#include <openvpn/openssl/pki/x509store.hpp>
#include <openvpn/openssl/bio/bio_memq_stream.hpp>

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
    typedef CertCRLListTemplate<X509List, CRLList> CertCRLList;

    enum {
      MAX_CIPHERTEXT_IN = 64
    };

    // The data needed to construct an OpenSSLContext.
    // Alternatively, SSLConfig can be used.
    struct Config
    {
      Config() : mode(SSLConfig::UNDEF), flags(0) {}

      SSLConfig::Mode mode;
      SSLConfig::Flags flags;
      CertCRLList ca;
      X509 cert;
      X509List extra_certs;
      PKey pkey;
      DH dh; // only needed in server mode
      Frame::Ptr frame;
    };

    // Represents an actual SSL session.
    // Normally instantiated by OpenSSLContext::ssl().
    class SSL : public RC<thread_unsafe_refcount>
    {
    public:
      enum {
	SHOULD_RETRY = -1
      };

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
	  if (ctx.mode() == SSLConfig::SERVER)
	    SSL_set_accept_state(ssl);
	  else if (ctx.mode() == SSLConfig::CLIENT)
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

      ~SSL()
      {
	ssl_erase();
      }

    private:
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

    typedef boost::intrusive_ptr<SSL> SSLPtr;

    explicit OpenSSLContext(const Config& config)
      : ctx_(NULL)
    {
      init(config);
    }

    explicit OpenSSLContext(const SSLConfig& config)
      : ctx_(NULL)
    {
      Config c;
      c.mode = config.mode;
      c.flags = config.flags;
      c.ca.parse_pem(config.ca, "CA_CRL_LIST");
      c.cert.parse_pem(config.cert);
      if (!config.extra_certs.empty())
	CertCRLList::from_string(config.extra_certs, "EXTRA_CERTS_LIST", &c.extra_certs, NULL);
      c.pkey.parse_pem(config.pkey);
      if (!config.dh.empty())
	c.dh.parse_pem(config.dh);
      c.frame = config.frame;
      init(c);
    }

    SSLPtr ssl() const { return SSLPtr(new SSL(*this)); }

    void update_trust(const CertCRLList& cc)
    {
      X509Store store(cc);
      SSL_CTX_set_cert_store(ctx_, store.move());
    }

    ~OpenSSLContext()
    {
      erase();
    }

    SSLConfig::Mode mode() const { return mode_; }
    SSLConfig::Flags flags() const { return flags_; }
    const Frame::Ptr& frame() const { return frame_; }
    SSL_CTX* raw_ctx() const { return ctx_; }

  private:
    // Print debugging information on SSL/TLS session negotiation.
    static void info_callback (const ::SSL *s, int where, int ret)
    {
      if (where & SSL_CB_LOOP)
	{
	  OPENVPN_LOG("SSL state (" << (where & SSL_ST_CONNECT ? "connect" : where & SSL_ST_ACCEPT ? "accept" : "undefined") << "): " << SSL_state_string_long(s));
	}
      else if (where & SSL_CB_ALERT)
	{
	  OPENVPN_LOG("SSL alert (" << (where & SSL_CB_READ ? "read" : "write") << "): " << SSL_alert_type_string_long(ret) << ": " << SSL_alert_desc_string_long(ret));
	}
    }

    void init(const Config& config)
    {
      try
	{
	  // Create new SSL_CTX for server or client mode
	  if (config.mode == SSLConfig::SERVER)
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
	  else if (config.mode == SSLConfig::CLIENT)
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
	  SSL_CTX_set_verify (ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); // fixme -- add verify callback
	  // fixme -- support SSL_CTX_set_cipher_list

	  // Set certificate
	  if (!config.cert.defined())
	    OPENVPN_THROW(ssl_context_error, "OpenSSLContext: cert not defined");
	  if (SSL_CTX_use_certificate(ctx_, config.cert.obj()) != 1)
	    throw OpenSSLException("OpenSSLContext: SSL_CTX_use_certificate failed");

	  // Set private key, fixme -- add support for private key encryption and external PKI
	  if (!config.pkey.defined())
	    OPENVPN_THROW(ssl_context_error, "OpenSSLContext: private key not defined");
	  if (SSL_CTX_use_PrivateKey(ctx_, config.pkey.obj()) != 1)
	    throw OpenSSLException("OpenSSLContext: SSL_CTX_use_PrivateKey failed");

	  // Set extra certificates that are part of our own certificate
	  // chain but shouldn't be included in the verify chain.
	  if (config.extra_certs.defined())
	    {
	      for (X509List::const_iterator i = config.extra_certs.begin(); i != config.extra_certs.end(); i++)
		{
		  if (SSL_CTX_add_extra_chain_cert(ctx_, (*i)->obj_dup()) != 1)
		    throw OpenSSLException("OpenSSLContext: SSL_CTX_add_extra_chain_cert failed");
		}
	    }

	  // Check cert/private key compatibility
	  if (!SSL_CTX_check_private_key(ctx_))
	    throw OpenSSLException("OpenSSLContext: private key does not match the certificate");

	  // Set CAs/CRLs
	  if (!config.ca.certs.defined())
	    OPENVPN_THROW(ssl_context_error, "OpenSSLContext: CA not defined");
	  update_trust(config.ca);

	  // Show handshake debugging info
	  if (config.flags & SSLConfig::DEBUG)
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

    void erase()
    {
      if (ctx_)
	{
	  SSL_CTX_free(ctx_);
	  ctx_ = NULL;
	}
    }

    SSLConfig::Mode mode_;
    SSLConfig::Flags flags_;
    Frame::Ptr frame_;
    SSL_CTX* ctx_;
  };

  typedef OpenSSLContext::Ptr OpenSSLContextPtr;

} // namespace openvpn

#endif // OPENVPN_OPENSSL_SSL_SSLCTX_H
