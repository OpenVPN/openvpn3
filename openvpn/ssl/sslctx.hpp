#ifndef OPENVPN_SSL_SSLCTX_H
#define OPENVPN_SSL_SSLCTX_H

#include <openvpn/common/types.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/openssl/error.hpp>
#include <openvpn/pki/x509.hpp>
#include <openvpn/pki/crl.hpp>
#include <openvpn/pki/pkey.hpp>
#include <openvpn/pki/dh.hpp>
#include <openvpn/pki/certcrl.hpp>
#include <openvpn/pki/x509store.hpp>

namespace openvpn {

  class SSLContext : public RC<thread_unsafe_refcount>
  {
  public:
    struct Parms
    {
      enum Mode {
	UNDEF,
	CLIENT,
	SERVER
      };

      Parms() : mode(UNDEF) {}

      Mode mode;
      CertCRLList ca;
      X509 cert;
      X509List extra_certs;
      PKey pkey;
      DH dh;
    };

    OPENVPN_EXCEPTION(ssl_context_error);

    SSLContext(const Parms& parms)
      : ctx_(NULL)
    {
      try
	{
	  // Create new SSL_CTX for server or client mode
	  if (parms.mode == Parms::SERVER)
	    {
	      ctx_ = SSL_CTX_new(TLSv1_server_method());
	      if (ctx_ == NULL)
		throw OpenSSLException("SSLContext: SSL_CTX_new failed for server method");

	      // Set DH object
	      if (!parms.dh.defined())
		OPENVPN_THROW(ssl_context_error, "SSLContext: DH not defined");
	      if (!SSL_CTX_set_tmp_dh(ctx_, parms.dh.obj()))
		throw OpenSSLException("SSLContext: SSL_CTX_set_tmp_dh failed");
	    }
	  else if (parms.mode == Parms::CLIENT)
	    {
	      ctx_ = SSL_CTX_new(TLSv1_client_method());
	      if (ctx_ == NULL)
		throw OpenSSLException("SSLContext: SSL_CTX_new failed for client method");
	    }
	  else
	    OPENVPN_THROW(ssl_context_error, "SSLContext: unknown parms.mode");

	  // Set SSL options
	  SSL_CTX_set_session_cache_mode(ctx_, SSL_SESS_CACHE_OFF);
	  SSL_CTX_set_options(ctx_, SSL_OP_SINGLE_DH_USE);
	  SSL_CTX_set_verify (ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); // fixme -- add verify callback
	  // fixme -- support SSL_CTX_set_cipher_list

	  // Set certificate
	  if (!parms.cert.defined())
	    OPENVPN_THROW(ssl_context_error, "SSLContext: cert not defined");
	  if (SSL_CTX_use_certificate(ctx_, parms.cert.obj()) != 1)
	    throw OpenSSLException("SSLContext: SSL_CTX_use_certificate failed");

	  // Set private key, fixme -- add support for private key encryption and external PKI
	  if (!parms.pkey.defined())
	    OPENVPN_THROW(ssl_context_error, "SSLContext: private key not defined");
	  if (SSL_CTX_use_PrivateKey(ctx_, parms.pkey.obj()) != 1)
	    throw OpenSSLException("SSLContext: SSL_CTX_use_PrivateKey failed");

	  // Set extra certificates that are part of our own certificate
	  // chain but shouldn't be included in the verify chain.
	  if (parms.extra_certs.defined())
	    {
	      for (X509List::const_iterator i = parms.extra_certs.begin(); i != parms.extra_certs.end(); i++)
		{
		  if (SSL_CTX_add_extra_chain_cert(ctx_, (*i)->obj_dup()) != 1)
		    throw OpenSSLException("SSLContext: SSL_CTX_add_extra_chain_cert failed");
		}
	    }

	  // Check cert/private key compatibility
	  if (!SSL_CTX_check_private_key(ctx_))
	    throw OpenSSLException("SSLContext: private key does not match the certificate");

	  // Set CAs/CRLs
	  if (!parms.ca.certs.defined())
	    OPENVPN_THROW(ssl_context_error, "SSLContext: CA not defined");
	  update_trust(parms.ca);
	}
      catch (...)
	{
	  erase();
	  throw;
	}
    }

    void update_trust(const CertCRLList& cc)
    {
      const X509Store store(cc);
      SSL_CTX_set_cert_store(ctx_, store.obj());
    }

    ~SSLContext()
    {
      erase();
    }

  private:
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

#endif // OPENVPN_SSL_SSLCTX_H
