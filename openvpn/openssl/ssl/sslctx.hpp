#ifndef OPENVPN_OPENSSL_SSL_SSLCTX_H
#define OPENVPN_OPENSSL_SSL_SSLCTX_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/pki/cclist.hpp>
#include <openvpn/ssl/sslconf.hpp>
#include <openvpn/openssl/util/error.hpp>
#include <openvpn/openssl/pki/x509.hpp>
#include <openvpn/openssl/pki/crl.hpp>
#include <openvpn/openssl/pki/pkey.hpp>
#include <openvpn/openssl/pki/dh.hpp>
#include <openvpn/openssl/pki/x509store.hpp>

namespace openvpn {

  class SSLContext : public RC<thread_unsafe_refcount>
  {
  public:
    typedef CertCRLListTemplate<X509List, CRLList> CertCRLList;

    struct Config
    {
      Config() : mode(SSLConfig::UNDEF) {}

      SSLConfig::Mode mode;
      CertCRLList ca;
      X509 cert;
      X509List extra_certs;
      PKey pkey;
      DH dh;
    };

    OPENVPN_EXCEPTION(ssl_context_error);

    explicit SSLContext(const Config& config)
      : ctx_(NULL)
    {
      init(config);
    }

    explicit SSLContext(const SSLConfig& config)
      : ctx_(NULL)
    {
      Config c;
      c.mode = config.mode;
      c.ca.parse_pem(config.ca, "CA_CRL_LIST");
      c.cert.parse_pem(config.cert);
      if (!config.extra_certs.empty())
	CertCRLList::from_string(config.extra_certs, "EXTRA_CERTS_LIST", &c.extra_certs, NULL);
      c.pkey.parse_pem(config.pkey);
      if (!config.dh.empty())
	c.dh.parse_pem(config.dh);
      init(c);
    }

    static void validate(const SSLConfig& config)
    {
      SSLContext context(config);
    }

    void update_trust(const CertCRLList& cc)
    {
      X509Store store(cc);
      SSL_CTX_set_cert_store(ctx_, store.move());
    }

    ~SSLContext()
    {
      erase();
    }

    SSL_CTX* raw_ctx() const { return ctx_; }    

  private:
    void init(const Config& config)
    {
      try
	{
	  // Create new SSL_CTX for server or client mode
	  if (config.mode == SSLConfig::SERVER)
	    {
	      ctx_ = SSL_CTX_new(TLSv1_server_method());
	      if (ctx_ == NULL)
		throw OpenSSLException("SSLContext: SSL_CTX_new failed for server method");

	      // Set DH object
	      if (!config.dh.defined())
		OPENVPN_THROW(ssl_context_error, "SSLContext: DH not defined");
	      if (!SSL_CTX_set_tmp_dh(ctx_, config.dh.obj()))
		throw OpenSSLException("SSLContext: SSL_CTX_set_tmp_dh failed");
	    }
	  else if (config.mode == SSLConfig::CLIENT)
	    {
	      ctx_ = SSL_CTX_new(TLSv1_client_method());
	      if (ctx_ == NULL)
		throw OpenSSLException("SSLContext: SSL_CTX_new failed for client method");
	    }
	  else
	    OPENVPN_THROW(ssl_context_error, "SSLContext: unknown config.mode");

	  // Set SSL options
	  SSL_CTX_set_session_cache_mode(ctx_, SSL_SESS_CACHE_OFF);
	  SSL_CTX_set_options(ctx_, SSL_OP_SINGLE_DH_USE);
	  SSL_CTX_set_verify (ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); // fixme -- add verify callback
	  // fixme -- support SSL_CTX_set_cipher_list

	  // Set certificate
	  if (!config.cert.defined())
	    OPENVPN_THROW(ssl_context_error, "SSLContext: cert not defined");
	  if (SSL_CTX_use_certificate(ctx_, config.cert.obj()) != 1)
	    throw OpenSSLException("SSLContext: SSL_CTX_use_certificate failed");

	  // Set private key, fixme -- add support for private key encryption and external PKI
	  if (!config.pkey.defined())
	    OPENVPN_THROW(ssl_context_error, "SSLContext: private key not defined");
	  if (SSL_CTX_use_PrivateKey(ctx_, config.pkey.obj()) != 1)
	    throw OpenSSLException("SSLContext: SSL_CTX_use_PrivateKey failed");

	  // Set extra certificates that are part of our own certificate
	  // chain but shouldn't be included in the verify chain.
	  if (config.extra_certs.defined())
	    {
	      for (X509List::const_iterator i = config.extra_certs.begin(); i != config.extra_certs.end(); i++)
		{
		  if (SSL_CTX_add_extra_chain_cert(ctx_, (*i)->obj_dup()) != 1)
		    throw OpenSSLException("SSLContext: SSL_CTX_add_extra_chain_cert failed");
		}
	    }

	  // Check cert/private key compatibility
	  if (!SSL_CTX_check_private_key(ctx_))
	    throw OpenSSLException("SSLContext: private key does not match the certificate");

	  // Set CAs/CRLs
	  if (!config.ca.certs.defined())
	    OPENVPN_THROW(ssl_context_error, "SSLContext: CA not defined");
	  update_trust(config.ca);
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

    SSL_CTX* ctx_;
  };

  typedef boost::intrusive_ptr<SSLContext> SSLContextPtr;

} // namespace openvpn

#endif // OPENVPN_OPENSSL_SSL_SSLCTX_H
