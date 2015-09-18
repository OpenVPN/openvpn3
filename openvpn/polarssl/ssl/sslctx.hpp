//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
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

// Wrap the PolarSSL 1.3 SSL API as defined in <polarssl/ssl.h>
// so that it can be used as the SSL layer by the OpenVPN core.

#ifndef OPENVPN_POLARSSL_SSL_SSLCTX_H
#define OPENVPN_POLARSSL_SSL_SSLCTX_H

#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <memory>

#include <polarssl/ssl.h>
#include <polarssl/oid.h>
#include <polarssl/sha1.h>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/base64.hpp>
#include <openvpn/common/binprefix.hpp>
#include <openvpn/frame/memq_stream.hpp>
#include <openvpn/pki/cclist.hpp>
#include <openvpn/pki/pkcs1.hpp>
#include <openvpn/ssl/sslconsts.hpp>
#include <openvpn/ssl/sslapi.hpp>

#include <openvpn/polarssl/pki/x509cert.hpp>
#include <openvpn/polarssl/pki/x509crl.hpp>
#include <openvpn/polarssl/pki/dh.hpp>
#include <openvpn/polarssl/pki/pkctx.hpp>
#include <openvpn/polarssl/util/error.hpp>

// An SSL Context is essentially a configuration that can be used
// to generate an arbitrary number of actual SSL connections objects.

// PolarSSLContext is an SSL Context implementation that uses the
// PolarSSL library as a backend.

namespace openvpn {

  namespace polarssl_ctx_private {
    static const int aes_cbc_ciphersuites[] = // CONST GLOBAL
      {
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	0
      };

    /*
     * This is a modified list from PolarSSL ssl_ciphersuites.c.
     * We removed some SHA1 methods near the top of the list to
     * avoid Chrome warnings about "obsolete cryptography".
     * We also removed ECDSA, CCM, PSK, and CAMELLIA algs.
     */
    static const int ciphersuites[] =
      {
	/* Selected AES-256 ephemeral suites */
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,

	/* Selected AES-128 ephemeral suites */
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,

	/* Selected remaining >= 128-bit ephemeral suites */
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,

	/* Selected AES-256 suites */
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_256_CBC_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,

	/* Selected AES-128 suites */
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA256,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,

	/* Selected remaining >= 128-bit suites */
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,

	0
      };
  }

  // Represents an SSL configuration that can be used
  // to instantiate actual SSL sessions.
  class PolarSSLContext : public SSLFactoryAPI
  {
  public:
    typedef RCPtr<PolarSSLContext> Ptr;

    enum {
      MAX_CIPHERTEXT_IN = 64 // maximum number of queued input ciphertext packets
    };

    // The data needed to construct a PolarSSLContext.
    class Config : public SSLConfigAPI
    {
      friend class PolarSSLContext;

    public:
      typedef RCPtr<Config> Ptr;

      Config() : external_pki(nullptr),
		 ssl_debug_level(0),
		 flags(0),
		 ns_cert_type(NSCert::NONE),
		 tls_version_min(TLSVersion::UNDEF),
		 local_cert_enabled(true),
		 enable_renegotiation(false),
                 force_aes_cbc_ciphersuites(false) {}

      virtual SSLFactoryAPI::Ptr new_factory()
      {
	return SSLFactoryAPI::Ptr(new PolarSSLContext(this));
      }

      virtual void set_mode(const Mode& mode_arg)
      {
	mode = mode_arg;
      }

      virtual const Mode& get_mode() const
      {
	return mode;
      }

      // if this callback is defined, no private key needs to be loaded
      virtual void set_external_pki_callback(ExternalPKIBase* external_pki_arg)
      {
	external_pki = external_pki_arg;
      }

      virtual void set_private_key_password(const std::string& pwd)
      {
	priv_key_pwd = pwd;
      }

      virtual void load_ca(const std::string& ca_txt, bool strict)
      {
	PolarSSLPKI::X509Cert::Ptr c = new PolarSSLPKI::X509Cert();
	c->parse(ca_txt, "ca", strict);
	ca_chain = c;
      }

      virtual void load_crl(const std::string& crl_txt)
      {
	PolarSSLPKI::X509CRL::Ptr c = new PolarSSLPKI::X509CRL();
	c->parse(crl_txt);
	crl_chain = c;
      }

      virtual void load_cert(const std::string& cert_txt)
      {
	PolarSSLPKI::X509Cert::Ptr c = new PolarSSLPKI::X509Cert();
	c->parse(cert_txt, "cert", true);
	crt_chain = c;
      }

      virtual void load_cert(const std::string& cert_txt, const std::string& extra_certs_txt)
      {
	PolarSSLPKI::X509Cert::Ptr c = new PolarSSLPKI::X509Cert();
	c->parse(cert_txt, "cert", true);
	if (!extra_certs_txt.empty())
	  c->parse(extra_certs_txt, "extra-certs", true);
	crt_chain = c;
      }

      virtual void load_private_key(const std::string& key_txt)
      {
	PolarSSLPKI::PKContext::Ptr p = new PolarSSLPKI::PKContext();
	p->parse(key_txt, "config", priv_key_pwd);
	priv_key = p;
      }

      virtual void load_dh(const std::string& dh_txt)
      {
	PolarSSLPKI::DH::Ptr mydh = new PolarSSLPKI::DH();
	mydh->parse(dh_txt, "server-config");
	dh = mydh;
      }

      virtual void set_frame(const Frame::Ptr& frame_arg)
      {
	frame = frame_arg;
      }

      virtual void set_debug_level(const int debug_level)
      {
	ssl_debug_level = debug_level;
      }

      virtual void set_flags(const unsigned int flags_arg)
      {
	flags = flags_arg;
      }

      virtual void set_ns_cert_type(const NSCert::Type ns_cert_type_arg)
      {
	ns_cert_type = ns_cert_type_arg;
      }

      virtual void set_remote_cert_tls(const KUParse::TLSWebType wt)
      {
	KUParse::remote_cert_tls(wt, ku, eku);
      }

      virtual void set_tls_remote(const std::string& tls_remote_arg)
      {
	tls_remote = tls_remote_arg;
      }

      virtual void set_tls_version_min(const TLSVersion::Type tvm)
      {
	tls_version_min = tvm;
      }

      virtual void set_tls_version_min_override(const std::string& override)
      {
	TLSVersion::apply_override(tls_version_min, override);
      }

      virtual void set_local_cert_enabled(const bool v)
      {
	local_cert_enabled = v;
      }

      virtual void set_enable_renegotiation(const bool v)
      {
	enable_renegotiation = v;
      }

      virtual void set_force_aes_cbc_ciphersuites(const bool v)
      {
	force_aes_cbc_ciphersuites = v;
      }

      virtual void set_rng(const RandomAPI::Ptr& rng_arg)
      {
	rng = rng_arg;
      }

      virtual std::string validate_cert(const std::string& cert_txt) const
      {
	PolarSSLPKI::X509Cert::Ptr cert = new PolarSSLPKI::X509Cert(cert_txt, "validation cert", true);
	return cert_txt; // fixme -- implement parse/re-render semantics
      }

      virtual std::string validate_cert_list(const std::string& certs_txt) const
      {
	PolarSSLPKI::X509Cert::Ptr cert = new PolarSSLPKI::X509Cert(certs_txt, "validation cert list", true);
	return certs_txt; // fixme -- implement parse/re-render semantics
      }

      virtual std::string validate_private_key(const std::string& key_txt) const
      {
	PolarSSLPKI::PKContext::Ptr pkey = new PolarSSLPKI::PKContext(key_txt, "validation", "");
	return key_txt; // fixme -- implement parse/re-render semantics
      }

      virtual std::string validate_dh(const std::string& dh_txt) const
      {
	PolarSSLPKI::DH::Ptr dh = new PolarSSLPKI::DH(dh_txt, "validation");
	return dh_txt; // fixme -- implement parse/re-render semantics
      }

      virtual std::string validate_crl(const std::string& crl_txt) const
      {
	PolarSSLPKI::X509CRL::Ptr crl = new PolarSSLPKI::X509CRL(crl_txt);
	return crl_txt; // fixme -- implement parse/re-render semantics
      }

      virtual void load(const OptionList& opt, const unsigned int lflags)
      {
	// client/server
	if (lflags & LF_PARSE_MODE)
	  mode = opt.exists("client") ? Mode(Mode::CLIENT) : Mode(Mode::SERVER);

	// possibly disable peer cert verification
	if ((lflags & LF_ALLOW_CLIENT_CERT_NOT_REQUIRED)
	    && opt.exists("client-cert-not-required"))
	  flags |= SSLConst::NO_VERIFY_PEER;

	// ca
	{
	  const std::string ca_txt = opt.cat("ca");
	  load_ca(ca_txt, true);
	}

	// CRL
	{
	  const std::string crl_txt = opt.cat("crl-verify");
	  if (!crl_txt.empty())
	    load_crl(crl_txt);
	}

	// local cert/key
	if (local_cert_enabled)
	  {
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

	// parse tls-remote
	tls_remote = opt.get_optional("tls-remote", 1, 256);

	// parse tls-version-min option
	{
#         if defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_3)
	    const TLSVersion::Type maxver = TLSVersion::V1_2;
#         elif defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_2)
	    const TLSVersion::Type maxver = TLSVersion::V1_1;
#         else
            const TLSVersion::Type maxver = TLSVersion::V1_0;
#         endif
	  tls_version_min = TLSVersion::parse_tls_version_min(opt, maxver);
	}

	// unsupported cert verification options
	{
	}
      }

    private:
      Mode mode;
      PolarSSLPKI::X509Cert::Ptr crt_chain;  // local cert chain (including client cert + extra certs)
      PolarSSLPKI::X509Cert::Ptr ca_chain;   // CA chain for remote verification
      PolarSSLPKI::X509CRL::Ptr crl_chain;   // CRL chain for remote verification
      PolarSSLPKI::PKContext::Ptr priv_key;  // private key
      std::string priv_key_pwd;              // private key password
      PolarSSLPKI::DH::Ptr dh;               // diffie-hellman parameters (only needed in server mode)
      ExternalPKIBase* external_pki;
      Frame::Ptr frame;
      int ssl_debug_level;
      unsigned int flags;           // defined in sslconsts.hpp
      NSCert::Type ns_cert_type;
      std::vector<unsigned int> ku; // if defined, peer cert X509 key usage must match one of these values
      std::string eku;              // if defined, peer cert X509 extended key usage must match this OID/string
      std::string tls_remote;
      TLSVersion::Type tls_version_min; // minimum TLS version that we will negotiate
      bool local_cert_enabled;
      bool enable_renegotiation;
      bool force_aes_cbc_ciphersuites;
      RandomAPI::Ptr rng;   // random data source
    };

    // Represents an actual SSL session.
    // Normally instantiated by PolarSSLContext::ssl().
    class SSL : public SSLAPI
    {
      // read/write callback errors
      enum {
	// assumes that PolarSSL user-defined errors may start at -0x8000
	CT_WOULD_BLOCK = -0x8000,
	CT_INTERNAL_ERROR = -0x8001
      };

      friend class PolarSSLContext;

    public:
      typedef RCPtr<SSL> Ptr;

      virtual void start_handshake()
      {
	ssl_handshake(ssl);
      }

      virtual ssize_t write_cleartext_unbuffered(const void *data, const size_t size)
      {
	const int status = ssl_write(ssl, (const unsigned char*)data, size);
	if (status < 0)
	  {
	    if (status == CT_WOULD_BLOCK)
	      return SSLConst::SHOULD_RETRY;
	    else if (status == CT_INTERNAL_ERROR)
	      throw PolarSSLException("SSL write: internal error");
	    else
	      throw PolarSSLException("SSL write error", status);
	  }
	else
	  return status;
      }

      virtual ssize_t read_cleartext(void *data, const size_t capacity)
      {
	if (!overflow)
	  {
	    const int status = ssl_read(ssl, (unsigned char*)data, capacity);
	    if (status < 0)
	      {
		if (status == CT_WOULD_BLOCK)
		  return SSLConst::SHOULD_RETRY;
		else if (status == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY)
		  return SSLConst::PEER_CLOSE_NOTIFY;
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

      virtual bool read_cleartext_ready() const
      {
	return !ct_in.empty() || ssl_get_bytes_avail(ssl);
      }

      virtual void write_ciphertext(const BufferPtr& buf)
      {
	if (ct_in.size() < MAX_CIPHERTEXT_IN)
	  ct_in.write_buf(buf);
	else
	  overflow = true;
      }

      virtual bool read_ciphertext_ready() const
      {
	return !ct_out.empty();
      }

      virtual BufferPtr read_ciphertext()
      {
	return ct_out.read_buf();
      }

      virtual std::string ssl_handshake_details() const
      {
	if (ssl)
	  {
	    const char *ver = ssl_get_version(ssl);
	    const char *cs = ssl_get_ciphersuite(ssl);
	    if (ver && cs)
	      return ver + std::string("/") + cs;
	  }
	return "";
      }

      virtual const AuthCert::Ptr& auth_cert() const
      {
	return authcert;
      }

      ~SSL()
      {
	erase();
      }

    private:
      SSL(PolarSSLContext* ctx, const char *hostname)
      {
	clear();
	try {
	  const Config& c = *ctx->config;
	  int status;

	  // set pointer back to parent
	  parent = ctx;

	  // init SSL object
	  ssl = new ssl_context;
	  status = ssl_init(ssl);
	  if (status < 0)
	    throw PolarSSLException("error in ssl_init", status);

	  // set client/server mode
	  if (c.mode.is_server())
	    {
	      ssl_set_endpoint(ssl, SSL_IS_SERVER);
	      authcert.reset(new AuthCert());
	    }
	  else if (c.mode.is_client())
	    ssl_set_endpoint(ssl, SSL_IS_CLIENT);
	  else
	    throw PolarSSLException("unknown client/server mode");

	  // set minimum TLS version
	  if (!c.force_aes_cbc_ciphersuites || c.tls_version_min > TLSVersion::UNDEF)
	    {
	      int polar_major;
	      int polar_minor;
	      switch (c.tls_version_min)
		{
		case TLSVersion::V1_0:
		default:
		  polar_major = SSL_MAJOR_VERSION_3;
		  polar_minor = SSL_MINOR_VERSION_1;
		  break;
#               if defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_2)
	          case TLSVersion::V1_1:
		    polar_major = SSL_MAJOR_VERSION_3;
		    polar_minor = SSL_MINOR_VERSION_2;
		    break;
#               endif
#               if defined(SSL_MAJOR_VERSION_3) && defined(SSL_MINOR_VERSION_3)
	          case TLSVersion::V1_2:
		    polar_major = SSL_MAJOR_VERSION_3;
		    polar_minor = SSL_MINOR_VERSION_3;
		    break;
#               endif
	        }
	      ssl_set_min_version(ssl, polar_major, polar_minor);
	    }

	  // peer must present a valid certificate
	  if (!(c.flags & SSLConst::NO_VERIFY_PEER))
	    ssl_set_authmode(ssl, SSL_VERIFY_REQUIRED);

	  // set verify callback
	  ssl_set_verify(ssl, c.mode.is_server() ? verify_callback_server : verify_callback_client, this);

	  // Notes on SSL resume/renegotiation:
	  // SSL resume on server side is controlled by ssl_set_session_cache.
	  // SSL renegotiation on/off is handled here via ssl_set_renegotiation.
	  // Without calling ssl_set_renegotiation, it defaults to
	  // SSL_RENEGOTIATION_DISABLED and ssl_legacy_renegotiation defaults to
	  // SSL_LEGACY_NO_RENEGOTIATION.  To enable session tickets,
	  // POLARSSL_SSL_SESSION_TICKETS (compile flag) must be defined
	  // in PolarSSL config.h.
	  ssl_set_renegotiation(ssl, c.enable_renegotiation ? SSL_RENEGOTIATION_ENABLED : SSL_RENEGOTIATION_DISABLED);

	  ssl_set_ciphersuites(ssl, c.force_aes_cbc_ciphersuites ?
			       polarssl_ctx_private::aes_cbc_ciphersuites :
			       polarssl_ctx_private::ciphersuites);

	  // set CA chain
	  if (c.ca_chain)
	    ssl_set_ca_chain(ssl,
			     c.ca_chain->get(),
			     c.crl_chain ? c.crl_chain->get() : nullptr,
			     hostname);
	  else
	    throw PolarSSLException("CA chain not defined");

	  // client cert+key
	  if (c.local_cert_enabled)
	    {
	      if (c.external_pki)
		{
		  // set our own certificate, supporting chain (i.e. extra-certs), and external private key
		  if (c.crt_chain)
		    ssl_set_own_cert_alt(ssl, c.crt_chain->get(), ctx, epki_decrypt, epki_sign, epki_key_len);
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
	  if (c.ssl_debug_level)
	    ssl_set_dbg(ssl, dbg_callback, ctx);
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
	  return actual > 0 ? (int)actual : CT_WOULD_BLOCK;
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
	  return (int)length;
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
	PolarSSLContext *self = (PolarSSLContext *)arg;
	if (level <= self->config->ssl_debug_level)
	  OPENVPN_LOG_NTNL("PolarSSL[" << level << "]: " << text);
      }

      void clear()
      {
	ssl = nullptr;
	overflow = false;
      }

      void erase()
      {
	if (ssl)
	  {
	    ssl_free(ssl);
	    delete ssl;
	  }
	clear();
      }

      PolarSSLContext *parent;
      ssl_context *ssl;	       // underlying SSL connection object
      RandomAPI::Ptr rng;      // random data source
      bool overflow;
      MemQStream ct_in;    // write ciphertext to here
      MemQStream ct_out;   // read ciphertext from here
      AuthCert::Ptr authcert;
    };

    /////// start of main class implementation

    // create a new SSL instance
    virtual SSLAPI::Ptr ssl()
    {
      return SSL::Ptr(new SSL(this, nullptr));
    }

    // like ssl() above but verify hostname against cert CommonName and/or SubjectAltName
    virtual SSLAPI::Ptr ssl(const std::string& hostname)
    {
      return SSL::Ptr(new SSL(this, hostname.c_str()));
    }

    virtual const Mode& mode() const
    {
      return config->mode;
    }
 
    ~PolarSSLContext()
    {
      erase();
    }

  private:
    PolarSSLContext(Config* config_arg)
      : config(config_arg)
    {
      if (config->local_cert_enabled)
	{
	  // Verify that cert is defined
	  if (!config->crt_chain)
	    throw PolarSSLException("cert is undefined");
	}
    }

    size_t key_len() const
    {
      return pk_get_size(&config->crt_chain->get()->pk) / 8;
    }

    // ns-cert-type verification

    bool ns_cert_type_defined() const
    {
      return config->ns_cert_type != NSCert::NONE;
    }

    bool verify_ns_cert_type(const x509_crt *cert) const
    {
      if (config->ns_cert_type == NSCert::SERVER)
	return bool(cert->ns_cert_type & NS_CERT_TYPE_SSL_SERVER);
      else if (config->ns_cert_type == NSCert::CLIENT)
	return bool(cert->ns_cert_type & NS_CERT_TYPE_SSL_CLIENT);
      else
	return false;
    }

    // remote-cert-ku verification

    bool x509_cert_ku_defined() const
    {
      return config->ku.size() > 0;
    }

    bool verify_x509_cert_ku(const x509_crt *cert)
    {
      if (cert->ext_types & EXT_KEY_USAGE)
	{
	  const unsigned int ku = cert->key_usage;
	  for (std::vector<unsigned int>::const_iterator i = config->ku.begin(); i != config->ku.end(); ++i)
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
      return !config->eku.empty();
    }

    bool verify_x509_cert_eku(x509_crt *cert)
    {
      if (cert->ext_types & EXT_EXTENDED_KEY_USAGE)
	{
	  x509_sequence *oid_seq = &cert->ext_key_usage;
	  while (oid_seq != nullptr)
	    {
	      x509_buf *oid = &oid_seq->buf;

	      // first compare against description
	      {
		const char *oid_str = x509_oid_get_description(oid);
		if (oid_str && config->eku == oid_str)
		  return true;
	      }

	      // next compare against OID numeric string
	      {
		char oid_num_str[256];
		const int status = x509_oid_get_numeric_string(oid_num_str, sizeof(oid_num_str), oid);
		if (status >= 0 && config->eku == oid_num_str)
		  return true;
	      }
	      oid_seq = oid_seq->next;
	    }
	}
      return false;
    }

    // Try to return the x509 subject formatted like the OpenSSL X509_NAME_oneline method.
    // Only attributes matched in the switch statements below will be rendered.  All other
    // attributes will be ignored.
    static std::string x509_get_subject(const x509_crt *cert)
    {
      std::string ret;
      for (const x509_name *name = &cert->subject; name != nullptr; name = name->next)
	{
	  const char *key = nullptr;
	  if (OID_CMP(OID_AT_CN, &name->oid))
	    key = "CN";
	  else if (OID_CMP(OID_AT_COUNTRY, &name->oid))
	    key = "C";
	  else if (OID_CMP(OID_AT_LOCALITY, &name->oid))
	    key = "L";
	  else if (OID_CMP(OID_AT_STATE, &name->oid))
	    key = "ST";
	  else if (OID_CMP(OID_AT_ORGANIZATION, &name->oid))
	    key = "O";
	  else if (OID_CMP(OID_AT_ORG_UNIT, &name->oid))
	    key = "OU";
	  else if (OID_CMP(OID_PKCS9_EMAIL, &name->oid))
	    key = "emailAddress";

	  // make sure that key is defined and value has no embedded nulls
	  if (key && !string::embedded_null((const char *)name->val.p, name->val.len))
	    ret += "/" + std::string(key) + "=" + std::string((const char *)name->val.p, name->val.len);
	}
      return ret;
    }

    static std::string x509_get_common_name(const x509_crt *cert)
    {
      const x509_name *name = &cert->subject;

      // find common name
      while (name != nullptr)
	{
	  if (OID_CMP(OID_AT_CN, &name->oid))
	    break;
	  name = name->next;
	}

      if (name)
	return std::string((const char *)name->val.p, name->val.len);
      else
	return std::string("");
    }

    static std::string fmt_polarssl_verify_flags(const int flags)
    {
      std::ostringstream os;
      if (flags & BADCERT_EXPIRED)
	os << "CERT_EXPIRED ";
      if (flags & BADCERT_REVOKED)
	os << "CERT_REVOKED ";
      if (flags & BADCERT_CN_MISMATCH)
	os << "CN_MISMATCH ";
      if (flags & BADCERT_NOT_TRUSTED)
	os << "CERT_NOT_TRUSTED ";
      if (flags & BADCRL_NOT_TRUSTED)
	os << "CRL_NOT_TRUSTED ";
      if (flags & BADCRL_EXPIRED)
	os << "CRL_EXPIRED ";
      if (flags & BADCERT_MISSING)
	os << "CERT_MISSING ";
      if (flags & BADCERT_SKIP_VERIFY)
	os << "CERT_SKIP_VERIFY ";
      if (flags & BADCERT_OTHER)
	os << "CERT_OTHER ";
      return os.str();
    }

    static std::string status_string(const x509_crt *cert, const int depth, const int *flags)
    {
      std::ostringstream os;
      std::string status_str = "OK";
      if (*flags)
	status_str = "FAIL " + fmt_polarssl_verify_flags(*flags);
      os << "VERIFY "
	 << status_str
	 << ": depth=" << depth
	 << std::endl << cert_info(cert);
      return os.str();
    }

    static int verify_callback_client(void *arg, x509_crt *cert, int depth, int *flags)
    {
      PolarSSLContext::SSL *ssl = (PolarSSLContext::SSL *)arg;
      PolarSSLContext *self = ssl->parent;
      bool fail = false;

      // log status
      if (self->config->flags & SSLConst::LOG_VERIFY_STATUS)
	OPENVPN_LOG_SSL(status_string(cert, depth, flags));

      // leaf-cert verification
      if (depth == 0)
	{
	  // verify ns-cert-type
	  if (self->ns_cert_type_defined() && !self->verify_ns_cert_type(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad ns-cert-type in leaf certificate");
	      fail = true;
	    }

	  // verify X509 key usage
	  if (self->x509_cert_ku_defined() && !self->verify_x509_cert_ku(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 key usage in leaf certificate");
	      fail = true;
	    }

	  // verify X509 extended key usage
	  if (self->x509_cert_eku_defined() && !self->verify_x509_cert_eku(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 extended key usage in leaf certificate");
	      fail = true;
	    }

	  // verify tls-remote
	  if (!self->config->tls_remote.empty())
	    {
	      const std::string subject = TLSRemote::sanitize_x509_name(x509_get_subject(cert));
	      const std::string common_name = TLSRemote::sanitize_common_name(x509_get_common_name(cert));
	      TLSRemote::log(self->config->tls_remote, subject, common_name);
	      if (!TLSRemote::test(self->config->tls_remote, subject, common_name))
		{
		  OPENVPN_LOG_SSL("VERIFY FAIL -- tls-remote match failed");
		  fail = true;
		}
	    }
	}

      if (fail)
	*flags |= BADCERT_OTHER;
      return 0;
    }

    static int verify_callback_server(void *arg, x509_crt *cert, int depth, int *flags)
    {
      PolarSSLContext::SSL *ssl = (PolarSSLContext::SSL *)arg;
      PolarSSLContext *self = ssl->parent;
      bool fail = false;

      if (depth == 1) // issuer cert
	{
	  // save the issuer cert fingerprint
	  if (ssl->authcert)
	    {
	      const int SHA_DIGEST_LENGTH = 20;
	      static_assert(sizeof(AuthCert::issuer_fp) == SHA_DIGEST_LENGTH, "size inconsistency");
	      sha1(cert->raw.p, cert->raw.len, ssl->authcert->issuer_fp);
	    }
	}
      else if (depth == 0) // leaf-cert
	{
	  // verify ns-cert-type
	  if (self->ns_cert_type_defined() && !self->verify_ns_cert_type(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad ns-cert-type in leaf certificate");
	      fail = true;
	    }

	  // verify X509 key usage
	  if (self->x509_cert_ku_defined() && !self->verify_x509_cert_ku(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 key usage in leaf certificate");
	      fail = true;
	    }

	  // verify X509 extended key usage
	  if (self->x509_cert_eku_defined() && !self->verify_x509_cert_eku(cert))
	    {
	      OPENVPN_LOG_SSL("VERIFY FAIL -- bad X509 extended key usage in leaf certificate");
	      fail = true;
	    }

	  if (ssl->authcert)
	    {
	      // save the Common Name
	      ssl->authcert->cn = x509_get_common_name(cert);

	      // save the leaf cert serial number
	      const x509_buf *s = &cert->serial;
	      if (s->len > 0 && s->len <= sizeof(ssl->authcert->sn))
		ssl->authcert->sn = bin_prefix_floor<decltype(ssl->authcert->sn)>(s->p, s->len, -1);
	      else
		ssl->authcert->sn = -1;
	    }
	}

      if (fail)
	*flags |= BADCERT_OTHER;
      return 0;
    }

    static std::string cert_info(const x509_crt *cert, const char *prefix = nullptr)
    {
      const size_t buf_size = 4096;
      std::unique_ptr<char[]> buf(new char[buf_size]);
      const int size = x509_crt_info(buf.get(), buf_size, prefix ? prefix : "", cert);
      if (size >= 0)
	return std::string(buf.get());
      else
	return "error rendering cert";
    }

    void erase()
    {
    }

    static int epki_decrypt(void *arg,
			    int mode,
			    size_t *olen,
			    const unsigned char *input,
			    unsigned char *output,
			    size_t output_max_len)
    {
      OPENVPN_LOG_SSL("PolarSSLContext::epki_decrypt is unimplemented, mode=" << mode
		      << " output_max_len=" << output_max_len);
      return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
    }

    static int epki_sign(void *arg,
			 int (*f_rng)(void *, unsigned char *, size_t),
			 void *p_rng,
			 int mode,
			 md_type_t md_alg,
			 unsigned int hashlen,
			 const unsigned char *hash,
			 unsigned char *sig)
    {
      PolarSSLContext *self = (PolarSSLContext *) arg;
      try {
	if (mode == RSA_PRIVATE)
	  {
	    size_t digest_prefix_len = 0;
	    const unsigned char *digest_prefix = nullptr;

	    /* get signature type */
	    switch (md_alg) {
	    case POLARSSL_MD_NONE:
	      break;
	    case POLARSSL_MD_MD2:
	      digest_prefix = PKCS1::DigestPrefix::MD2;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::MD2);
	      break;
	    case POLARSSL_MD_MD5:
	      digest_prefix = PKCS1::DigestPrefix::MD5;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::MD5);
	      break;
	    case POLARSSL_MD_SHA1:
	      digest_prefix = PKCS1::DigestPrefix::SHA1;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::SHA1);
	      break;
	    case POLARSSL_MD_SHA256:
	      digest_prefix = PKCS1::DigestPrefix::SHA256;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::SHA256);
	      break;
	    case POLARSSL_MD_SHA384:
	      digest_prefix = PKCS1::DigestPrefix::SHA384;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::SHA384);
	      break;
	    case POLARSSL_MD_SHA512:
	      digest_prefix = PKCS1::DigestPrefix::SHA512;
	      digest_prefix_len = sizeof(PKCS1::DigestPrefix::SHA512);
	      break;
	    default:
	      OPENVPN_LOG_SSL("PolarSSLContext::epki_sign unrecognized hash_id, mode=" << mode
			      << " md_alg=" << md_alg << " hashlen=" << hashlen);
	      return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
	    }

	    /* concatenate digest prefix with hash */
	    BufferAllocated from_buf(digest_prefix_len + hashlen, 0);
	    if (digest_prefix_len)
	      from_buf.write(digest_prefix, digest_prefix_len);
	    from_buf.write(hash, hashlen);

	    /* convert from_buf to base64 */
	    const std::string from_b64 = base64->encode(from_buf);

	    /* get signature */
	    std::string sig_b64;
	    const bool status = self->config->external_pki->sign("RSA_RAW", from_b64, sig_b64);
	    if (!status)
	      throw ssl_external_pki("PolarSSL: could not obtain signature");

	    /* decode base64 signature to binary */
	    const size_t len = self->key_len();
	    Buffer sigbuf(sig, len, false);
	    base64->decode(sigbuf, sig_b64);

	    /* verify length */
	    if (sigbuf.size() != len)
	      throw ssl_external_pki("PolarSSL: incorrect signature length");

	    /* success */
	    return 0;
	  }
	else
	  {
	    OPENVPN_LOG_SSL("PolarSSLContext::epki_sign unrecognized parameters, mode=" << mode 
			    << " md_alg=" << md_alg << " hashlen=" << hashlen);
	    return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
	  }
      }
      catch (const std::exception& e)
	{
	  OPENVPN_LOG("PolarSSLContext::epki_sign: " << e.what());
	  return POLARSSL_ERR_RSA_BAD_INPUT_DATA;
	}
    }

    static size_t epki_key_len(void *arg)
    {
      PolarSSLContext *self = (PolarSSLContext *) arg;
      return self->key_len();
    }

    Config::Ptr config;
  };

} // namespace openvpn

#endif
